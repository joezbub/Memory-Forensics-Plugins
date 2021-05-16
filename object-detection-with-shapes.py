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
python_objects_not_important = 0
python_objects_important = 0
false_positives = 0
recovered_c_structs = 0

def extract_data(addr_space, num_elements, buf):
    ct = 0
    ret = []
    while (ct != num_elements):
        found_object = obj.Object("float32",
                                offset=buf,
                                vm=addr_space)
        if (ct < 3):
            print found_object.val
        if not isinstance(found_object.val, float):
            return []
        else:
            ret.append(found_object.val)
        buf += 4
        ct += 1

    return ret


def find_tensors(task, addr_space, num_elements_dict, data_ptrs, amt_repeat):
    #only 3 tensors for each kernel/bias bc of optimizers
    heaps = []
    for vma in task.get_proc_maps(): #get heaps
        if vma.vm_name(task) == "[heap]":
            heaps.append(vma)

    tot_amt = len(data_ptrs) * amt_repeat # if we hit this number, break
    vis = set()

    weight_candidates = {}
    
    global false_positives
    global recovered_c_structs

    for heap in heaps:
        tmp = heap.vm_end / 8 * 8  #make sure divisible by 8
        end = (heap.vm_start + 7) / 8 * 8
        print "from", hex(int(tmp)), "to", hex(int(end))

        #tmp = 0x592ef80 #remove later
        
        while tmp != end: #begin search
            
            found_object = obj.Object("_Tensor1",
                            offset=tmp,
                            vm=addr_space)
             
            if (int(found_object.num_elements) in num_elements_dict):
                                
                for tup in num_elements_dict[int(found_object.num_elements)]:
                    name = tup[0]
                    arr = tup[1]
                    #if len(data_ptrs[name]) == amt_repeat or found_object.buf_.dereference().data_ in vis:
                    #    continue
                    shape_valid = True
                    for i in range(len(arr)):
                        if (arr[i] != int(found_object.shape[i])):
                            shape_valid = False
                            break
                    if (shape_valid and found_object.is_valid()):
                        data_ptrs[name].add(found_object.buf_.dereference().data_)
                        #vis.add(found_object.buf_.dereference().data_)
                        print
                        print name, "works"
                        print "num_elements", found_object.num_elements
                        print "obj_offset", hex(found_object.obj_offset)
                        print "vtable ptr (0x7fffc949bc48 for PID 1657):", hex(found_object.buf_.dereference().vtable_ptr)
                        print "data_ ptr:", hex(found_object.buf_.dereference().data_)
                        print tot_amt - len(vis), "left"
                        recovered_c_structs += 3
                        if name not in weight_candidates:
                            weight_candidates[name] = [extract_data(addr_space, found_object.num_elements, int(found_object.buf_.dereference().data_))]
                        else:
                            weight_candidates[name].append(extract_data(addr_space, found_object.num_elements, int(found_object.buf_.dereference().data_)))
                        
                        break
                    elif shape_valid and not found_object.is_valid():
                        false_positives += 1
            if len(vis) == tot_amt:
                break

            tmp -= 8 #from end to beginning

    print "\ndone with extraction\n"
    
    for key in data_ptrs:
        if (key not in weight_candidates):
            weight_candidates[key] = []

    return weight_candidates


def get_avg(weights, inds):
    curr = 0.0
    for x in inds:
        curr += abs(weights[x])
    return curr / float(len(inds))


def sample(arr):
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
    
    global python_objects_not_important
    global python_objects_important

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
        
        if found_object.ob_type.dereference().name in class_names and found_object.in_dict.dereference().val['name'] == "signature_wrapper":
            print "Found", found_object.ob_type.dereference().name, "at", hex(found_object.obj_offset)
            """
            print "tp_basicsize:", found_object.ob_type.dereference().tp_basicsize
            print "tp_dictoffset:", found_object.ob_type.dereference().tp_dictoffset
            print "in_dict pointer:", hex(found_object.in_dict)
            print "Num items in dict:", found_object.in_dict.dereference().ma_used
            print "ma_version_tag:", found_object.in_dict.dereference().ma_version_tag
            print "ma_keys pointer:", hex(found_object.in_dict.dereference().ma_keys)
            print "ma_values pointer:", hex(found_object.in_dict.dereference().ma_values)
            print
            """
            model_dict = found_object.in_dict.dereference().val
            python_objects_important += 2
            
            print model_dict['name']
            #print model_dict['_weak_variables']
            if (len(model_dict['_weak_variables'])):
                print (model_dict['_weak_variables'][0].ob_type.dereference().name)
            
            all_layers = []
            for var in model_dict['_weak_variables']:
                python_objects_important += 2
                model_layer = var.val
                all_layers.append(var)
            print all_layers

            ret = {}
            data_ptrs = {}
            shape = OrderedDict()
            
            print "Number of layers:", len(all_layers)
            
            for layer in all_layers:
                print
                layer_dict = layer.in_dict.dereference().val
                print layer_dict['_handle_name']
                
                if (layer_dict['_trainable'] == False):
                    print "Not Trainable"
                    continue

                if any(x in layer_dict['_handle_name'] for x in ["BatchNorm", "_bn", "batchnorm"]):
                    print "bn"
                    continue

                print "Shape:", layer_dict['_shape'].val
                shape[layer_dict['_handle_name']] = layer_dict['_shape'].val
                tot = 1
                for x in layer_dict['_shape'].val:
                    tot *= x
                if (tot not in ret):
                    ret[tot] = [(layer_dict['_handle_name'], layer_dict['_shape'].val)]
                else:
                    ret[tot].append((layer_dict['_handle_name'], layer_dict['_shape'].val))
                    
                data_ptrs[layer_dict['_handle_name']] = set()
            print len(shape) 
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
            print ret
            print shape
            print dups
            
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
                #pool = sample(pool) #random samples, gets averages, and sorts by descending
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
                final[key] = []
                for x in weights[key]:
                    final[key].append(x)
                #pool = sample(pool)
            
            print "MODEL SUMMARY"
            out_dict = {'model_name': "obj_detect_mobilenetv1_0", 'num_elements': tot_num_elements, 'tensors': {}}
            for key in shape:
                print key
                print shape[key]
                if (key in final):
                    curr_dict = {'shape': shape[key], 'weights': final[key]}
                    out_dict['tensors'][key] = curr_dict
                    print "Weights added to weights.txt"
                    #f.write(key + "\n")
                    #f.write(str(shape[key]) + "\n")
                    #for arr in final[key]:
                    #    f.write(str(arr) + "\n")
                    #f.write("\n")
                print
            
            #with open("obj_detect_resnet-shapes-correct" + "-weights.txt", 'w') as f:
            #   json.dump(out_dict, f)

            if (len(dups) == 0):
                print "No Duplicate Tensors"
            else:
                print "Duplicate Tensors Found (weights match any of them):"
                for key in dups:
                    tmp = dups[key]
                    tmp.append(key)
                    print tmp
            """
            f = open("obj_detect_resnet_0_1_weights.txt", "r")
            correct_dump = json.load(f)
            print ("Correct model_name: {}".format(correct_dump['model_name']))
            print("Received model_name: {}".format(out_dict['model_name']))
            print ("Correct num_elements: {}".format(correct_dump['num_elements']))
            print ("Received num_elements: {}\n".format(out_dict['num_elements']))
            missing = 0
            ct = 0
            sum_diff = 0
            shape_comp = 0
            diff_layers = []

            for layer in correct_dump['tensors']:
                if (layer in out_dict['tensors']):
                    print (layer)
                    if(correct_dump['tensors'][layer]['shape'] != out_dict['tensors'][layer]['shape']):
                        print ("Shapes different!")
                        shape_comp += 1
                    correct_arr = correct_dump['tensors'][layer]['weights']
                    diff = 1e9
                    best = []
                    pos = []
                    for arr in out_dict['tensors'][layer]['weights']:
                        if (len(arr) == 0):
                            continue
                        curr = 0
                        curr_pos = []
                        for i in range(len(correct_arr)):
                            if (arr[i] != correct_arr[i]):
                                curr_pos.append(i)
                                curr += 1

                        if (curr < diff):
                            diff = curr
                            pos = curr_pos
                            best = arr
                    if (diff == 1e9):
                        print "No Valid Tensors"
                    else:
                        print("{} weights different".format(diff))
                        sum_diff += diff
                    if diff > 0:
                        diff_layers.append(layer)
                    print "\n"

                else:
                    ct += 1
                    missing += len(correct_dump['tensors'][layer]['weights'])
                    print ("{} not found\n".format(layer))

            print (diff_layers)
            print (len(diff_layers))
            print ("{} layers not found".format(ct))
            print ("{} shapes not match".format(shape_comp))
            print ("{} out of {} found weights are different".format(sum_diff, correct_dump['num_elements'] - missing))
            """ 
            print "python important count", python_objects_important
            print "python not important count", python_objects_not_important
            print "false positive c count", false_positives
            print "recovered_c_structs", recovered_c_structs

            return True
        else:
            python_objects_not_important += 1
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
            start=pyruntime.gen3_next, #pid 1755 = 0x7ffff017d9d0 - 32, pid 2866 = 0x7ffff017d950 - 32
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


class obj_detect_weights_shapes(linux_pslist.linux_pslist):
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
            find_instance(task, ["FuncGraph"]) 
        
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
