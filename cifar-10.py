import ctypes
import os
import re
import struct
import sys
import time
import timeit
import io
import json
import random
from collections import OrderedDict

from itertools import groupby

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils

PROFILE_PATH = "./Scripts/ScriptOutputs/profile_py.txt"  # PATH TO PYTHON PROFILE
PROFILE_DATA = None

def extract_data(addr_space, num_elements, buf):
    ct = 0
    ret = []
    while (ct != num_elements):
        found_object = obj.Object("float32",
                                offset=buf,
                                vm=addr_space)
        if (ct < 3):
            print found_object.val
        if not isinstance(found_object.val, float): #invalid tensor
            return []
        else:
            ret.append(found_object.val)
        buf += 4
        ct += 1

    return ret


def find_tensors(task, addr_space, num_elements_dict, data_ptrs, amt_repeat):
    heaps = []
    for vma in task.get_proc_maps(): #get heaps
        if vma.vm_name(task) == "[heap]":
            heaps.append(vma)

    tot_amt = len(data_ptrs) * amt_repeat # if we hit this number, break
    vis = set()

    weight_candidates = {}

    for heap in heaps:
        tmp = heap.vm_end / 8 * 8  #make sure divisible by 8
        end = (heap.vm_start + 7) / 8 * 8
        print "from", hex(int(tmp)), "to", hex(int(end))
        
        while tmp != end: #begin search
            
            found_object = obj.Object("_Tensor1",
                            offset=tmp,
                            vm=addr_space)
            
            if (found_object.is_valid() and int(found_object.num_elements) in num_elements_dict):
                                
                for tup in num_elements_dict[int(found_object.num_elements)]:
                    name = tup[0]
                    arr = tup[1]
                    if len(data_ptrs[name]) == amt_repeat or found_object.buf_.dereference().data_ in vis:
                        continue
                    shape_valid = True
                    for i in range(len(arr)):
                        if (arr[i] != int(found_object.shape[i])):
                            shape_valid = False
                            break
                    if (shape_valid and found_object.buf_.dereference().vtable_ptr == 0x7fffc949bc48):
                        data_ptrs[name].add(found_object.buf_.dereference().data_)
                        vis.add(found_object.buf_.dereference().data_)
                        print
                        print name, "works"
                        print "num_elements", found_object.num_elements
                        print "obj_offset", hex(found_object.obj_offset)
                        print "vtable ptr (0x7fffc949bc48 for PID 1657):", hex(found_object.buf_.dereference().vtable_ptr)
                        print "data_ ptr:", hex(found_object.buf_.dereference().data_)
                        print tot_amt - len(vis), "left"
                        #print data_ptrs

                        if name not in weight_candidates:
                            weight_candidates[name] = [extract_data(addr_space, found_object.num_elements, int(found_object.buf_.dereference().data_))]
                        else:
                            weight_candidates[name].append(extract_data(addr_space, found_object.num_elements, int(found_object.buf_.dereference().data_)))
                        
                        break
            
            if len(vis) == tot_amt:
                break

            tmp -= 8 #from end to beginning

    print "\ndone with extraction\n"
    return weight_candidates


def get_avg(weights, inds):
    curr = 0.0
    for x in inds:
        curr += abs(weights[x])
    return curr / float(len(inds))


def sample(arr):
    #sample 10% of weights and get average, filter out optimizers
    for pair in arr:
        weights = pair[1]
        n = len(weights)
        if (n <= 30):
            pair[0] = get_avg(weights, range(n))
        elif (n <= 300):
            inds = random.sample(xrange(n), 30)
            pair[0] = get_avg(weights, inds)
        else:
            inds = random.sample(xrange(n), n / 10)
            inds.sort()
            pair[0] = get_avg(weights, inds)
    arr.sort(reverse=True)
    return arr


def traverse_gc(task, addr_space, obj_type_string, start, stop, class_names):
    """
    Traverses the garbage collector doubly linked list, searches for Sequential.
    - 136883 -> 149033 objects found for trained MNIST
    - After trained, Sequential moved to Generation 3
    """
    tmp = start
    
    while True:
        found_head = obj.Object("_PyGC_Head", offset=tmp, vm=addr_space)
        found_object = obj.Object("_PyInstanceObject1",
                            offset=tmp + 32,
                            vm=addr_space)
        
        if not found_head.is_valid():
            print "_PyGC_Head invalid"
            sys.exit(0)
            
        print "curr:", hex(tmp), "next:", hex(found_head.next_val), "prev:", hex(found_head.prev_val)
        print found_object.ob_type.dereference().name
        
        if found_object.ob_type.dereference().name in class_names:
            print "Found", found_object.ob_type.dereference().name, "at", hex(found_object.obj_offset)

            model_dict = found_object.in_dict.dereference().val

            all_layers = [] #iterate through model layers and append valid layers (not model classes)

            for i in range(len(model_dict['_layers'])):
                model_layer = model_dict['_layers'][i].in_dict.dereference().val
                if (len(model_layer['_layers']) > 0 and model_dict['_layers'][i].ob_type.dereference().name != "BatchNormalization"): #if this model_layer is instead a model
                    print model_layer['_name']
                    for j in range(len(model_layer['_layers'])):
                        model_layer1 = model_layer['_layers'][j].in_dict.dereference().val
                        if (len(model_layer1['_layers']) > 0 and model_layer['_layers'][j].ob_type.dereference().name != "BatchNormalization"):
                            print model_layer1['_name']
                            for k in range(len(model_layer1['_layers'])):
                                model_layer2 = model_layer1['_layers'][k].in_dict.dereference().val
                                all_layers.append(model_layer1['_layers'][k])
                        else:
                            all_layers.append(model_layer['_layers'][j])
                else:
                    all_layers.append(model_dict['_layers'][i])
            print all_layers

            ret = {}
            data_ptrs = {}
            shape = OrderedDict()
            
            print "Number of layers:", len(all_layers)
            
            for layer in all_layers:
                print
                layer_dict = layer.in_dict.dereference().val
                print layer_dict['_name']
                print layer_dict

                #if (layer.ob_type.dereference().name == "BatchNormalization"):
                #    continue

                if ("input" in layer_dict['_name']):
                    shape[layer_dict['_name']] = list(layer_dict['_batch_input_shape'])
                    print "Input Shape:", list(layer_dict['_batch_input_shape'])
                    continue

                if ("max_pooling" in layer_dict['_name'] or "average_pooling" in layer_dict['_name']):
                    shape[layer_dict['_name']] = layer_dict['pool_size']
                    print "Pool Size:", layer_dict['pool_size']
                    continue

                if ("dropout" in layer_dict['_name']):
                    shape[layer_dict['_name']] = layer_dict['rate']
                    print "Rate:", layer_dict['rate']
                    continue

                if ("_pad" in layer_dict['_name']):
                    shape[layer_dict['_name']] = layer_dict['padding']
                    print "Padding:", layer_dict['padding']
                    continue


                if not layer_dict.has_key("_trainable_weights"):
                    print "No Trainable Weights Key"
                    continue

                print "amt of trainable weights:", len(layer_dict['_trainable_weights'])
                
                for j in range(len(layer_dict['_trainable_weights'])):
                    model_weights = layer_dict['_trainable_weights'][j].in_dict.dereference().val
                    print "Name:", model_weights['_handle_name']
                    print "Shape:", model_weights['_shape'].val
                    shape[model_weights['_handle_name']] = model_weights['_shape'].val

                    tot = 1
                    for x in model_weights['_shape'].val:
                        tot *= x
                    if (tot not in ret):
                        ret[tot] = [(model_weights['_handle_name'], model_weights['_shape'].val)]
                    else:
                        ret[tot].append((model_weights['_handle_name'], model_weights['_shape'].val))
                    
                    data_ptrs[model_weights['_handle_name']] = set()
                        
            dups = {}
            tot_num_elements = 0
            for num in ret:
                tot_num_elements += num * len(ret[num])
                ret[num].sort(key=lambda x:x[1])
                mem = ret[num][0]
                for i in range(1, len(ret[num])): #detect duplicate shapes
                    if (mem[1] == ret[num][i][1]):
                        if (mem[0] not in dups):
                            dups[mem[0]] = [ret[num][i][0]]
                        else:
                            dups[mem[0]].append(ret[num][i][0])
                    else:
                        mem = ret[num][i]
            
            print "Total elements:", tot_num_elements
            print ret #dictionary {num_elements: (model_name, shape)
            print shape #OrderedDict {model_name: shape}
            print dups #dictionary {model_name: names with identical shapes}
            
            weights = find_tensors(task, addr_space, ret, data_ptrs, 1) #3 is hardcoded (optimizers + 1)
            
            final = {}

            #must aggregate all identical tensor shapes in one pool to filter out optimizers
            for key in dups:
                pool = []
                for x in weights[key]:
                    pool.append([0.0, x])
                for name in dups[key]:
                    for x in weights[name]:
                        pool.append([0.0, x])
                pool = sample(pool) #random samples, gets averages, and sorts by descending
                must_be_weights = [] #the greatest averages must be weights
                for i in range(len(pool) / 1):
                    must_be_weights.append(pool[i][1])

                final[key] = must_be_weights
                for name in dups[key]:
                    final[name] = must_be_weights

            #handle distinct tensors now
            for key in weights:
                pool = []
                if (key in final):
                    continue
                for x in weights[key]:
                    pool.append([0.0, x])
                pool = sample(pool)
                final[key]= []
                for i in range(len(pool) / 1):
                    final[key].append(pool[i][1])

            print "MODEL SUMMARY"
            out_dict = {'model_name': model_dict['_name'], 'num_elements': tot_num_elements, 'tensors': {}}
            for key in shape:
                print key
                print shape[key]
                if (key in final):
                    curr_dict = {'shape': shape[key], 'weights': final[key]}
                    out_dict['tensors'][key] = curr_dict
                    print "Weights added to weights.txt"

                print
            
            with open(model_dict["_name"] + "-weights.txt", 'w') as f:
                json.dump(out_dict, f)

            if (len(dups) == 0):
                print "No Duplicate Tensors"
            else:
                print "Duplicate Tensors Found (weights match any of them):"
                for key in dups:
                    tmp = dups[key]
                    tmp.append(key)
                    print tmp

            return True
        
        if (tmp == stop):
            break
        tmp = found_head.next_val
    return False


def get_profile_data():
    with open(PROFILE_PATH) as json_file:
        profile_data = json.load(json_file)
    return profile_data


def find_PyRuntime():
    profile_data = get_profile_data()
    for p in profile_data['globals']:
        if p['name'] == '_PyRuntime':
            return int(p['offset'],16)
    return -1


def find_instance(task, class_names):
    """
    Go to _PyRuntimeState -> gc -> generations -> Traverse PyGC_Head pointers
    """
    
    start = timeit.default_timer()

    addr_space = task.get_process_address_space() 

    _PyRuntimeLoc = find_PyRuntime()

    print "_PyRuntime", hex(_PyRuntimeLoc)

    if _PyRuntimeLoc == -1:
        print "Failed to find any _pyruntime location"
        sys.exit(0)
    
    pyruntime = obj.Object("_PyRuntimeState",
                                  offset=_PyRuntimeLoc, #0xaa6560
                                  vm=addr_space)

    if not pyruntime.is_valid():
        print "Not _PyRuntimeState"
        sys.exit(0)
    
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen1_next,
            stop=pyruntime.gen1_prev,
           class_names=class_names)):
           return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen2_next,
            stop=pyruntime.gen2_prev,
            class_names=class_names)):
            return
    if (traverse_gc(task=task, 
            addr_space=addr_space,
            obj_type_string="_PyGC_Head",
            start=pyruntime.gen3_next,
            stop=pyruntime.gen3_prev,
            class_names=class_names)):
            return
    
    print "Sequential not found"
    return


def _is_python_task(task, pidstr):
    """
    Checks if the task has the specified Python PID
    """
    if str(task.pid) != pidstr:
        return False
    else:
        return True


class cifar_10_weights(linux_pslist.linux_pslist):
    """
    Recovers Tensorflow model attributes from a Python process.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'PID', short_option = 'p', default = None,
                          help = 'Operate on the Python Process ID',
                          action = 'store', type = 'str')

    def _validate_config(self):
        if self._config.PID is not None and len(self._config.PID.split(',')) != 1:
            debug.error("Please enter the process PID")
        
    def calculate(self):
        """
        Runtime stats:
        Finding Sequential takes 5 minutes
        Brute force through heap (for tensor objects) takes: 2.1 min / 10 MB
        Total about: 15 minutes (depends on how tensors are spread out)
        """
        start = timeit.default_timer()
        linux_common.set_plugin_members(self)

        self._validate_config()
        pidstr = self._config.PID

        tasks = []
        for task in linux_pslist.linux_pslist.calculate(self):
            if _is_python_task(task, pidstr):
                tasks.append(task)

        for task in tasks:
            find_instance(task, ["Sequential"]) 
        
        stop = timeit.default_timer()
        print("\nRuntime: {0} seconds".format(stop - start))
        sys.exit(0)

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Name", str)],
                        self.generator(data))

    def generator(self, data):
        """
        Generate data that may be formatted for printing.
        """
        for instance in data:
            yield (0, [str(instance.string)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Dict", "70")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])