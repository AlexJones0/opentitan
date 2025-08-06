# Flash Endurance Testing

Testing the endurance of embedded flash depends on the vendor-specific flash macros that are used, and may involve physical processes such as baking a chip at high temperatures to emulate flash retention and wear over a long period of time.

Thus, the flash endurance test (see `//sw/device/tests:flash_endurance_test`) uses a command-driven implementation that is independent of any specific target thresholds being tested.
Command JSON files are executed by the host, which tell the device to carry out a sequence of operations on the embedded flash and to verify and log the results.
The test results and output logs can be used to determine the endurance of the flash compared to target thresholds.

## Running flash endurance tests

You can execute the flash endurance test like other Bazel targets, but it is advised to use `bazel run` as the test can run on for a very long time depending on the configured command.
You can alternatively configure a maximal timeout value.
For example, running on FPGA:

```sh
# Run with `bazel run`
./bazelisk.sh run //sw/device/tests:flash_endurance_test_fpga_cw340_sival_rom_ext
# Or run with `bazel test` with a large timeout
./bazelisk.sh test --test_output=streamed --test_timeout=2147483647 //sw/device/tests:flash_endurance_test_fpga_cw340_sival_rom_ext
```

The test will refuse to run until you provide **explicit acknowledgement** that running the test may have permanent destructive outcomes (wearing down flash).
You are always required to provide acknowledgement, even on non-silicon targets.
After reading the warning, you can add an argument to provide your acknowledgement:
```sh
# Run the test, providing acknowledgement
./bazelisk.sh run //sw/device/tests:flash_endurance_test_fpga_cw340_sival_rom_ext --test_arg=--acknowledge-test-action
```

By default, the test uses the [`example_endurance_test.json`](./example_endurance_test.json) command file.
To override the test and use a custom JSON file, the preferred method is to pass in the `--command-file` test argument, which must be an absolute path (prefix with `$PWD/` if necessary).
Note that if you give multiple command files, only the first file will be used.
Alternatively, you can manually edit the Bazel test target to point to your command JSON, so that the command file is integrated with the Bazel test.

```sh
# Run the test, specifying a custom command file `test.json`
./bazelisk.sh run //sw/device/tests:flash_endurance_test_fpga_cw340_sival_rom_ext --test_arg=--command-file="$PWD/test.json" --test_arg=--acknowledge-test-action
```

## Logging test outputs

For tests that use the `ProgramErase` command, the device will report back information every time a configured number of cycles has passed.
By default, this information is dumped to the standard output, but this can optionally be routed to a new CSV file using the `--log-file` test argument, e.g.

```sh
# Log the P/E results to `/tmp/flash_log.csv`
./bazelisk.sh run //sw/device/tests:flash_endurance_test_fpga_cw340_sival_rom_ext --test_arg=--log-file="/tmp/flash_test_log.csv", --test_arg=--acknowledge-test-action
```

Again, be sure that this is provided as an absolute path.
To avoid accidentally overwriting logs for tests split into multiple parts, the test will error if the given log file already exists.

In the example command file, we test 25 cycles and set the logging granularity to be every 5 cycles.
This might output something like:

```csv
cycle,success,ecc_errors,cumulative_erase_micros,cumulative_program_micros,cumulative_read_micros
5,true,0,194,7761,2012
10,true,0,381,15520,4019
15,true,0,574,23281,6029
20,true,0,769,31043,8041
25,true,0,958,38804,10051
```

For each log result, the cumulative time taken so far for erase, program and read operations are stored.
This CSV can then be processed by higher-level scripts to compute relevant statistics and visualizations of the flash wear and performance as it is used.

## Command File Format

For reference, see the [example JSON file](./example_endurance_test.json) used by default for FPGA and silicon targets, reproduced below:

```json
{
    "page_num": null,
    "boot_slot": "SlotB",
    "high_endurance_en": false,
    "scramble_en": false,
    "ecc_en": false,
    "commands": [
        {
            "ProgramErase": {
                "num_cycles": 25,
                "log_granularity": 5,
                "readback_delay_us": 100,
                "allow_ecc_errors": true,
                "test_data": "0xa5a5a5a5",
                "invert_each_cycle": false
            }
        },
        {
          "ResetTarget": {
                "repetitions": 2
          }
        },
        {
            "WritePage": {
                "readback_delay_us": 2000,
                "data": "01234567 89ABCDEF FACECAFE DEADBEEF 5A5AA5A5"
            }
        },
        {
            "Wait": {
                "duration": "1s"
            }
        },
        {
            "ReadPage": {
                "expected_data": "01234567 89ABCDEF FACECAFE DEADBEEF 5A5AA5A5"
            }
        }
    ]
}
```

Command files are written in a simple JSON format, which starts by describing some initial attributes configured for testing:
 - `page_num` (optional): The number of the page being tested.
 A value of `null` can be used to configure the test to find and use the last working page of flash.
 Note that for Earlgrey there are 256 pages per data partition, so `132` would refer to page 132 of Bank 0, whereas `511` refers to page 255 of Bank 1.
 - `boot_slot` (optional): Set to either `"SlotA"` or `"SlotB"` to configure which slot the test is run from.
 Executing from slot A allows you to test pages in flash Bank 1, whereas executing from slot B allows you to test pages in flash Bank 0.
 - `high_endurance_en`: Whether to enable the [high endurance property](../../../../../../hw/top_earlgrey/ip_autogen/flash_ctrl/doc/registers.md#mp_region_cfg) for the tested page.
 - `scramble_en`: Whether to enable [scrambling](../../../../../../hw/top_earlgrey/ip_autogen/flash_ctrl/doc/registers.md#mp_region_cfg) for the tested page.
 - `ecc_en`: Whether to enable [error correction codes](../../../../../../hw/top_earlgrey/ip_autogen/flash_ctrl/doc/registers.md#mp_region_cfg) for the tested page.
 - `commands`: The list of commands to execute during the test - see the below [command reference](#Command_Reference).

### Command Reference

Test commands are serialized in the form `{ "CommandName": { ... attributes ... } }`, where the following commands are available:
 - `ProgramErase`: run a test that repeatedly erases a page, reads it back, programs it, and reads it back, to wear down flash over a number of cycles.
 This has several attributes:
   - `num_cycles`: the number of cycles to test.
   - `log_granularity` (optional, default 1): the frequency with which the device reports test information to the host, which is optionally written to the log CSV.
   Test data will be logged every `log_granularity` cycles.
   - `readback_delay_us` (optional, default 0): an optional delay between erasing/programming data and reading it back, measured in microseconds.
   - `allow_ecc_errors` (optional, default `true`): if ECC is enabled, this configures whether single ECC errors that are automatically corrected should be allowed (counted as succeeding) or not.
   - `test_data` (optional, default `"0xA5"`): a hex string containing the data to be written in the test.
   This will be duplicated/truncated as needed to fit the size of a page.
   - `invert_each_cycle` (optional, default `true`): if enabled, every other cycle of the test will use a bitwise-inverted copy of the test data to stress the flash.
 - `WritePage`: Erase a page and write some data to it, reading it back to check that the write succeeded.
   - `readback_delay_us` (optional, default 0): an optional delay between erasing/programming data and reading it back, measured in microseconds.
   - `data`:  a hex string containing the data to be written to the page.
   This will be duplicated/truncated as needed to fit the size of a page.
 - `ReadPage`: read a page from flash and compare it to some expected value:
   - `expected_data`: a hex string containing the data that is expected to be read back.
    This will be duplicated/truncated as needed to fit the size of a page.
 - `Wait`: do nothing for a specified duration.
   - `duration`: the time to wait, as a human-readable string, e.g. `"duration": "1h 23m 45s"`.
 - `ResetTarget`: reset the target, booting the test again.
   After all resets have been processed, this is automatically followed by a command to re-apply the initial testing configuration.
   - `repetitions` (optional, default 1): The number of times to reset the target.

## Testing with manual intervention

You may want to run an endurance test with manual intervention.
For example, you may want to disconnect and bake a chip at high temperatures after running a Program/Erase test and writing some data, to simulate wear over an extended period of time (which is infeasible to test otherwise). You would then want to subsequently read the flash data back to check whether the data is retained, or a fault has occurred.

The recommended flow for doing this is to split the test into multiple phases, giving each  its own JSON command file.
These phases should be decided so that they are separated by these required manual steps.
You can then load each test JSON individually with its own Bazel invocation, providing a separate command and log file each time.

One important detail to note is that regular bootstrapping of OpenTitan will clear the flash between each test run, causing previous page programs to be erased upon execution of a subsequent test phase.
Hence, after the first phase is run, you should add the `--skip-bootstrap` test argument to all Bazel commands to avoid this issue.
This requires that no other code was bootstrapped onto the device between the different test phases.

An example of a generic embedded flash endurance test that supports this flow can be found in [`manual_example_phase_1.json`](./manual_example_phase_1.json) and [`manual_example_phase_2.json`](./manual_example_phase_2.json), reproduced below.

In phase 1, we run 100,000 program-erase cycles and end by writing some data to the page.
We specifically test page 500 (page 244 of Bank 1):

```json
{
    "page_num": 500,
    "boot_slot": "SlotA",
    "high_endurance_en": false,
    "scramble_en": false,
    "ecc_en": false,
    "commands": [
        {
            "ProgramErase": {
                "num_cycles": 100000,
                "log_granularity": 500,
                "readback_delay_us": 2500,
                "allow_ecc_errors": true,
                "test_data": "0xa5a5a5a5",
                "invert_each_cycle": true
            }
        },
        {
            "WritePage": {
                "readback_delay_us": 10000,
                "data": "01234567 89ABCDEF FACECAFE DEADBEEF 5A5AA5A5"
            }
        }
    ]
}
```

After running this phase we could physically bake the chip at a high temperature for a few hours.
We then reconnect OpenTitan and run phase 2, where we read back page 500 after manual intervention and check that the test data matches the values that were programmed:

```json
{
    "page_num": 500,
    "boot_slot": "SlotA",
    "high_endurance_en": false,
    "scramble_en": false,
    "ecc_en": false,
    "commands": [
        {
            "ReadPage": {
                "expected_data": "01234567 89ABCDEF FACECAFE DEADBEEF 5A5AA5A5"
            }
        }
    ]
}

```

The commands we might use to test this are:

```sh
# Run part 1 and log into part_1_results.csv
./bazelisk.sh run //sw/device/tests:flash_endurance_test_silicon_owner_sival_rom_ext --test_arg=--command-file="$PWD/sw/host/tests/chip/flash_ctrl/endurance_tests/manual_example_phase_1.json" --test_arg=--log-file="/tmp/part_1_results.csv" --test_arg=--acknowledge-test-action

# ... do the manual baking here ...

# Run part 2 and log into part_2_results.csv, making sure to skip bootstrapping
./bazelisk.sh run //sw/device/tests:flash_endurance_test_silicon_owner_sival_rom_ext --test_arg=--command-file="$PWD/sw/host/tests/chip/flash_ctrl/endurance_tests/manual_example_phase_2.json" --test_arg=--log-file="/tmp/part_2_results.csv" --test_arg=--skip-bootstrap --test_arg=--acknowledge-test-action
```

By inspecting the test output and the two CSV files, we could then determine whether the flash's endurance supports our desired characteristics.

If you are running a test with multiple phases like this where the flash could practically fail, it is best to hard-code a specific page for testing via the `page_num` attribute.
This is because a failure induced in any manual step could cause a different page to be located and picked for testing instead.
Alternatively, you could run the first phase with `"page_num": null` to find the last working page, and then hard-code this value into subsequent test JSONs before running them.
import