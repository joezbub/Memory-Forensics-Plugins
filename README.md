# CARLA Volatility Plugins
Volatility plugins to find self-driving car information on a [CARLA](https://carla.org) memory dump. Currently, I have two plugins: `linux_python_brute_strings` and `testplug`.

# How to Use This Repository

Clone this repository into your Volatility directory.

## linux_find_instances
To execute the plugin found in `python-find-instances.py`, execute the following:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_find_instances -p *Python API PID*</code></pre>

This will carve out all the HUD instance object information from the Python process memory. After finding deallocated and allocated HUD objects with a brute force, the plugin uses the map of the instance dictionary (lines 526-554) to detect and verify each CPython Object. This map is customizable and can be used for any Python process memory (not just CARLA). Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information.

## linux_python_strings
To execute the plugin found in `python-brute-strings.py`, execute the following:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_python_brute_strings -p *Python API PID*</code></pre>

This will find all CPython string objects in your Python process memory (located in heaps) by checking if each address is the start of a PyStringObject. This brute force search will be able to yield deallocated (not yet overwritten) strings. Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information.

## testplug
`testplug.py` just lists all the processes names and their corresponding PIDs. Run it by executing:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* testplug</code></pre>