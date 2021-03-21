# Memory Forensics Plugins
Volatility plugins to recover machine learning model attributes. Currently, there are five plugins: `linux_find_instances3`, `linux_python3_strings`, `linux_find_instances`, `linux_python2_strings`, and `testplug`.

# Usage
Clone this repository into your Volatility directory. Install dependencies for `profileGen.py` through `pip install pyelftools` (must be Python 3). Make sure that the input path in `python-gc-traverse.py` and the output paths in `profileGen.py` are correct.

To use the following plugins, we need to create a json profile of the python binary for the Volatility plugin. Run the script `profileGen.py` with `python3 profileGen.py ./ELFs/*PYTHON BINARY*`, and a profile should be generated in `ScriptOutputs`.

## linux_find_instances3
To execute the plugin found in `python3-gc-traverse.py`, execute:
<pre><code>$ python vol.py --plugins=./Memory-Forensics-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_find_instances3 -p *Python PID*</code></pre>

Address of _PyRuntime will be read from input path taken from profileGen.py. The plugin will verify the address of the _PyRuntime struct and proceed to traverse through the Python's Garbage Collector generations which generally track instances of non-atomic types. It will identify the keras model and recover weights, shapes, and biases.

Still under testing phase. Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information. Tested on Python 3.7.5

## linux_python3_strings
To execute the plugin found in `python3-brute-strings.py`, execute:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_python_brute_strings -p *Python PID*</code></pre>

This will find all CPython unicode objects in the Python process memory (located in heaps) by checking if each address is a _PyASCIIObject. Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information. Tested on Python 3.7.5

## linux_find_instances
To execute the plugin found in `python2-find-instances.py`, execute the following:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_find_instances -p *Python PID*</code></pre>

This will carve out all the HUD instance object information from the Python process memory. After finding deallocated and allocated HUD objects with a brute force, the plugin uses the map of the instance dictionary (lines 526-554) to detect and verify each CPython Object. This map is customizable and can be used for any Python process memory (not just CARLA). Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information. Only works for Python 2.7.18

## linux_python2_strings
To execute the plugin found in `python2-brute-strings.py`, execute:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_python_brute_strings -p *Python PID*</code></pre>

This will find all CPython string objects in the Python process memory (located in heaps) by checking if each address is a PyStringObject. Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information. Tested on Python 2.7.18

## testplug
`testplug.py` just lists all the processes names and their corresponding PIDs. Run it by executing:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* testplug</code></pre>