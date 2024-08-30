# Flow Log Processing

## Overview
This script processes flow log records by mapping protocol numbers to protocol names and tagging records based on a provided lookup table. It supports both the default AWS flow log format (Version 2) and custom formats. The script produces output files that include tag counts and port/protocol combination counts.

## Features

**Protocol Mapping:** This feature maps protocol numbers to their corresponding names by using a CSV file.

**Tagging:** It assigns tags to flow log entries based on a lookup table.

**Custom Format Handling:** This feature supports custom flow log formats where fields can be in different positions.

**Command-Line Flexibility:** It allows for specifying root directories for test cases using command-line arguments.

## Assumptions 

**Protocol Mapping:**

* The protocol mapping CSV file is in the format taken from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml.

* The script expects a header row that is skipped during processing.

**Lookup Table:**

* The lookup table CSV file is in the format: dstport,protocol,tag.
* Entries in the lookup table are case-insensitive.

**Flow Logs:**

* Flow logs follow the AWS default flow log format (Version 2) unless a custom format is specified.(Referenced from https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
* The flow log entries have at least 14 fields as per the default format.

**Custom Formats:**

* The script can handle custom flow log formats by specifying the field positions for dstport and protocol_number.

**Output:**

* The output is generated as text files containing the tag counts and port/protocol combination counts.

## Installation and Setup

### Prerequisites
* Python 3.x
* `argparse` module (usually included in Python standard library)
* The following CSV files must be available:
  * `protocol_numbers_mapping.csv` for protocol mappings
  * `lookup_table.csv` for the lookup table
  * `flow_logs.csv` for flow log entries

## Instructions to Run

* Default run:
  * This will use the default paths:
    * `Lookup/lookup_table.csv`
    * `FlowLogsInput/flow_logs.csv`
    * `Output/output.txt`
  * Simply run the script with default file paths
```bash
python3 LogProcessor.py
```
* Run with a Custom Root Directory:
  * This will adjust paths as:
    * `TestCase1/Lookup/lookup_table.csv`
    * `TestCase1/FlowLogsInput/flow_logs.csv`
    * `TestCase1/Output/output.txt`
  * Specify a root directory (e.g., `TestCase1`) to run TestCase1 to use different file paths
```bash
python3 LogProcessor.py --test TestCase1
```
* Run with Custom Format:
   * To process logs with a custom format, modify the `main()` function to include the custom log format.
   * For example, custom format with dstport at index 8, protocol_number at index 9 as shown below:
```bash
custom_format = [('dstport', 8), ('protocol_number', 9)] 

port_proto_tag, tags_count, port_proto_combo = process_flow_logs_extended(
    flow_file='flow_logs.csv',
    lookup_table=lookup_table,
    protocol_map=protocol_map,
    log_format=custom_format
)
```

## Testing
### Test Cases
Several test cases were created to ensure the robustness of the script. These include:

* **Basic Functionality:** Testing with simple, straightforward flow logs and lookup table entries.
* **Duplicate Tags and Port/Protocol Combos:** Ensuring the script correctly counts duplicates.
* **Custom Log Format:** Validating that the script handles non-standard log formats by specifying custom field indices.

## How Tests Were Conducted:
* Test cases were organized into separate directories (`TestCase1`, `TestCase2`, etc.). 
* Each directory contained subdirectories for `Lookup/`, `FlowLogsInput/`, and `Output/`.
* The script was run with the `--test` argument pointing to each test case directory. 
* The output was then compared against the expected results to validate correctness.

## Analysis
* **Efficiency:** The script is designed to handle large log files efficiently by processing lines one at a time and using dictionaries to quickly store and look up data.
* **Flexibility:** The use of command-line arguments and the ability to specify custom formats make the script versatile for various scenarios.
* **Extensibility:** The code structure allows for easy extensions, such as adding new fields to the lookup table or supporting additional custom formats.

## Conclusion
This script provides a robust solution for processing flow logs, mapping protocols, and tagging entries based on a lookup table. With its flexible structure and comprehensive handling of various scenarios, it should meet the needs of most users requiring flow log processing capabilities.

## License

[MIT](https://choosealicense.com/licenses/mit/)