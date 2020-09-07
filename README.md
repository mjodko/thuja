# Thuja

This is a quick-and-dirty integration of [Tuya](https://www.tuya.com/) devices for [Home Assistant](https://www.home-assistant.io/).
In contrast to the [built-in integration](https://www.home-assistant.io/integrations/tuya/), Thuja operates entirely locally and doesn't
require an Internet connection.

Thuja is a self-contained integration meaning that it doesn't require any external Python packages to work.


## Important notes

- Currently, only switches (with single or multiple gangs) and covers are supported,
  as those are the only kinds of Tuya devices I own.
- Thuja has been tested only with devices using the 3.2 protocol version.
- While devices using the 3.3 protocol version might work, ones using 3.1 most likely will not. 
- In order to use Thuja, you will need to extract device identifiers and keys.
  This can be done using [tuyapi/cli](https://github.com/TuyaAPI/cli).
- I created this integration with just personal use in mind. If there is any interest in
  making it into a real integration (i.e. adding support for other protocol versions and
  device types, extracting communication logic into a supporting library and merging Thuja
  into the core of HA), I might consider working on it. Any contributions are obviously welcome. 


## Installation

### HACS

This integration is not currently available in the default repository list.

### Manual install

Place the `custom_components/thuja` folder under `custom_components` in your configuration directory.
Note that you may need to create a `custom_components` directory first if this is your first custom component in HA.


## Configuration

Thuja doesn't currently support configuration flows, so all configuration must go into your `configuration.yaml`.

Example:

```yaml
switch:
  - platform: thuja
    name: Bedroom Lights
    ip_address: 192.168.1.33
    id: bf63621a47bcabf863vnjt
    token: ab3338e5abd98091
    switches:
      - id: 1
        name: Ceiling
      - id: 2
        name: Walls

cover:
  - platform: thuja
    name: Guest Bedroom Blinds
    ip_address: 192.168.1.98
    id: bf4abf861a47bc4v262kjt
    token: cd98b33308e5ab92
```

## Command line interface

There is an experimental command line interface provided by Thuja. To start it, run `custom_components/thuja/thuja/cli.py` as a module:

```bash
$ python3 -m custom_components.thuja.thuja.cli \
    -i 192.168.1.33 \
    -d bf63621a47bcabf863vnjt \
    -k ab3338e5abd98091 \
    -c 2
```

You can then control the device using single key commands:

- `u` - update datapoint values
- `t` - toggle datapoint values
- `#` - toggle datapoint with index `#` (1-9)
- `f` - turn all datapoints off
- `n` - turn all datapoints on
- `q` - quit

For a full reference of available command line options, run it with the `--help` flag.

Note: The command line interface only works with Python 3.7+ on Unix systems
and currently is only useful for controlling binary switches.


## Credits

Device communication in Thuja is largely based on the [TuyaFace](https://github.com/TradeFace/tuyaface) library.

For AES encryption, a version of [pyaes](https://github.com/ricmoo/pyaes) is embedded in this integration in order
to avoid the need for any external (especially not pure-Python) libraries to be installed. 
