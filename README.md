# CARLA Volatility Plugins
Volatility plugins to find self-driving car information on a [CARLA](https://carla.org) memory dump. Currently, I have two plugins: `linux_python_brute_strings` and `testplug`.

# How to Use This Repository

Clone this repository into your Volatility directory.

## linux_python_strings
To execute the plugin found in `python-brute-strings.py`, execute the following:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* linux_python_brute_strings -p *Python API PID*</code></pre>

This will find all CPython string objects in your Python process memory (located in heaps). Note that you must specify exactly ONE Python process in the form of --pid=PID or -p PID. See --help for more information.

## testplug
`testplug.py` just lists all the processes names and their corresponding PIDs. Run it by executing:
<pre><code>$ python vol.py --plugins=./CARLA-Volatility-Plugins/ --profile=*YOUR LINUX PROFILE* -f *PATH TO MEMORY DUMP* testplug</code></pre>