# AI Psychiatry Volatility Plugins
Volatility plugins to extract Tensorflow model internals from a memory dump. The three plugins, `mnist_weights` in `mnist.py`, `cifar_10_weights` in `cifar-10.py`, and `obj_detect_weights_shapes` in `object-detection-with-shapes.py`, are relevant to our evaluation (they correspond to each model type). The other plugins are more basic and are meant to recover singular Python objects for demonstration purposes.

Our experiments were conducted on VirtualBox VMs running Ubuntu 18.04 (image: 5.3.0-62-generic) with 8-16 GB RAM. Note that Garbage Collector generations are only accessible using Python 3.7+ and `venv`. Our plugin cannot locate the Runtime struct using Anaconda environments.

# Usage
Clone this repository into your Volatility directory. Install dependencies for `profileGen.py`:

`pip install pyelftools`

Make sure that the input path in `python-gc-traverse.py` and the output paths in `profileGen.py` are correct. Create a json profile of the python binary running in your target VM. Run `profileGen.py`:

`python3 profileGen.py ./ELFs/*PYTHON BINARY*`

A profile should be generated in `ScriptOutputs`.

To execute plugins, cd into the volatility directory and execute:
<pre><code>$ python vol.py --plugins=./AI-Psychiatry/ --profile=*LINUX PROFILE* -f *PATH TO MEMORY DUMP* *PLUGIN NAME* -p *Python PID*</code></pre>

# Plugin Details

## mnist_weights
The plugin traverses through the Python Garbage Collector generations to recover the model instance. Then, it extracts all tensor shapes in the model by iterating through the `__dict__` and identifying the `TensorShape` object. It proceeds to extract the tensor weights by searching through the memory heap region for the shapes previously found. The complete recovered model is written to a json file with data like number of weights and potential weight arrays for each tensor.

The code was specifically designed for Keras Sequential model for the MNIST dataset. Because optimizer tensors are present in the heap, it finds three of each tensor and returns the one with the highest average.

`mnist.py` contains the definitions for all the VTypes used for the following plugins.

Tested on Python 3.7.5 

## cifar_10_weights
Implementation is the same as `mnist_weights`.

Designed to recover both `mobilenetv1` and `VGG16` detection models. Because these models are much larger than the simple MNIST model, expect a longer runtime (about 3 hours). Tensorflow also optimizes out the optimizer tensors, so they are not present in the memory heap region.

Tested on Python 3.7.5

## obj_detect_weights_shapes
Because the object detection experiments use `tf.saved_model` internally, we had to write a different plugin for this model type. After identifying the saved_model's `FuncGraph`, we recover its `_weak_variables` which contain the relevant tensors and perform the heap traversal.

Designed for our object detection experiments, involving `efficientdet`, `mobilenetv1` and `resnet` models with varying alphas. These models are the largest, especially resnet, so the runtime spans from 2-5 hours.

Tested on Python 3.7.5

## obj_detect_weights
Implementation slightly differs from the previous three plugins because it initially loads ground truth shapes from a json file and then performs the heap search. Otherwise, the plugin is similar to `obj_detect_weights_shapes`.

Tested on Python 3.7.5

## linux_find_instances
This plugin from `python2-find-instances.py` will carve out all the HUD instance object information from the Python process memory. After finding deallocated and allocated HUD objects with a brute force, the plugin uses the map of the instance dictionary (lines 526-554) to detect and verify each CPython Object. This map is customizable and can be used for any Python process memory (not just CARLA).

Tested on Python 2.7.18

## linux_python3_strings
This plugin from `python3-brute-strings.py` will find all CPython unicode objects (the new string type) in the Python process memory by checking if each address is a PyASCIIObject.

Tested on Python 3.7.5

## linux_python2_strings
This plugin from `python2-brute-strings.py` will find all CPython string objects in the Python process memory by checking if each address is a PyStringObject.

Tested on Python 2.7.18

## testplug
Lists all the processes names and their corresponding PIDs.