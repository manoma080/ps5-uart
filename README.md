## Typical build

```
mkdir build && cd build && cmake -GNinja .. && cmake --build .
```

Outputs will be placed in `bin/`. You'll want to program your pi pico with `bin/uart.uf2`, then run `tool.py`. See [uart/README.md](uart/README.md) for pico wiring instructions.

## Usage

From `tool.py` interactive shell, `emc.screset()` will perform reset of syscon (EMC) and bring the rest of the board into consistent state. `emc.unlock()` runs the EMC exploit, which unlocks access to the full set of EMC commands (UCMD protocol).


`emc.unlock_efc()` will exploit EFC and load `bin_blobs/uart_shell.cpp` onto it. `uart_client.py` is used for interacting with `uart_shell.cpp`.
