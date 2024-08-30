import csv
from collections import defaultdict, Counter
import os
import argparse

def load_protocol_mapping(protocol_file):
    """ Load protocol mappings from a CSV file taken from iana.org into a dictionary.
        For example: mapping protocol 6 -> TCP.
    Args:
        protocol_file (str): Path to the CSV file containing protocol mappings.
    Return:
        dict: A dictionary mapping protocol numbers (str) to protocol names (str).
    """
    protocol_map = {}
    with open(protocol_file, 'r') as pf:
        reader = csv.reader(pf)
        # Skipping the header row, if any
        next(reader) 
        for row in reader:
            # Getting the protocol number
            protocol_number = row[0].strip() 
            # Getting the corresponding protocol name
            protocol_name = row[1].strip() 
            protocol_map[protocol_number] = protocol_name
    return protocol_map

def load_lookup_table(lookup_file):
    """ Load lookup table from a CSV file into a dictionary.
    Args:
        lookup_file (str): Path to the CSV file containing lookup table data.
    Returns:
        dict: A dictionary where the key is a tuple (dstport, protocol) and the value is the corresponding tags.
    """
    # A dictionary where the key is a tuple (dstport, protocol) and the value is a set of tags.
    lookup_table = defaultdict(str) 
    with open(lookup_file, 'r') as lf:
        reader = csv.reader(lf)
        # Skipping the header row
        next(reader) 
        for row in reader:
            #Converting into lower case to handle case-insensitivity
            # Fetching destination port
            dstport = row[0].strip().lower()  
            # Fetchingc protocol name
            protocol = row[1].strip().lower() 
            # Fetching associated tag
            tag = row[2].strip().lower()
            # Filling the lookup table      
            lookup_table[(dstport, protocol)] = tag
    return lookup_table

def process_flow_logs(flow_file, lookup_table, protocol_map):
    """ 
    Process flow log records, map protocol numbers to protocol names, and tag records based on the lookup table.
    Args:
        flow_file (str): Path to the file containing flow logs.
        lookup_table (dict): A dictionary containing the lookup table data.
        protocol_map (dict): A dictionary mapping protocol numbers to protocol names. 
    Returns:
        port_proto_tag (list): A list of tuples (dstport, protocol, tag) for each flow log entry.
        tags_count (dict): A dictionary counting occurrences of each tag.
        port_proto_combo (list): A list of tuples (dstport, protocol) to count occurrences of each combination.
    """
    # To store counts of each tag
    tags_count = defaultdict(int) 
    # To store (dstport, protocol, tag) for each entry
    port_proto_tag = [] 
    # To store (dstport, protocol) combinations
    port_proto_combo = [] 


    with open(flow_file, 'r') as ff:
        for line in ff:
            parts = line.split()
            # Skipping line with less less than 14 columns
            if len(parts) < 14:
                continue  
            # Fetching destination port from the flow log
            dstport = parts[6].strip() 
            # Fetching protocol number (in decimal) from the flow log
            protocol_number = parts[7].strip().lower() 
            # Mapping protocol number to protocol name
            protocol = protocol_map.get(protocol_number, "unknown").lower() 
            key = (dstport, protocol) 
            
            # Retrieving the tag(s) from the lookup table or use "untagged"
            tag = str(lookup_table.get(key, "untagged")) 
            # Storing the (dstport, protocol, tag) tuple
            port_proto_tag.append((dstport, protocol, tag)) 
            # Incrementing the count for this tag
            tags_count[tag] += 1  
            # Storing the (dstport, protocol) combination
            port_proto_combo.append((dstport, protocol)) 

    return port_proto_tag, tags_count, port_proto_combo

def process_flow_logs_extended(flow_file, lookup_table, protocol_map,  log_format=None):
    """ 
    This is the extended version of above function. It accepts a new parameter "log_format" to handle custom formats.
    Process flow log records, map protocol numbers to protocol names, and tag records based on the lookup table.

    This version supports both default and custom flow log formats.
    
    Args:
        flow_file (str): Path to the file containing flow logs.
        lookup_table (dict): A dictionary containing the lookup table data.
        protocol_map (dict): A dictionary mapping protocol numbers to protocol names.
        log_format (list): A list defining the order and fields of the custom log format. 
                           Each element is a tuple ('field_name', index).
    Returns:
        port_proto_tag (list): A list of tuples (dstport, protocol, tag) for each flow log entry.
        tags_count (dict): A dictionary counting occurrences of each tag.
        port_proto_combo (list): A list of tuples (dstport, protocol) to count occurrences of each combination.
    """
    # To store counts of each tag
    tags_count = defaultdict(int) 
    # To store (dstport, protocol, tag) for each entry
    port_proto_tag = [] 
    # To store (dstport, protocol) combinations
    port_proto_combo = [] 

    if log_format is None:
        # Default format of version 2 indices
        log_format = [
            ('dstport', 6),
            ('protocol_number', 7)
        ]


    with open(flow_file, 'r') as ff:
        for line in ff:
            parts = line.split()
            # Skipping line with less less than 14 columns
            if len(parts) < 14:
                continue  
            # Fetching destination port from the flow log as per custom log format
            dstport = parts[log_format[0][1]].strip() 
            # Fetching protocol number (in decimal) from the flow log as per custom log format
            protocol_number = parts[log_format[1][1]].strip().lower() 
            # Mapping protocol number to protocol name
            protocol = protocol_map.get(protocol_number, "unknown").lower() 
            key = (dstport, protocol) 
            
            # Retrieving the tag(s) from the lookup table or use "untagged"
            tag = str(lookup_table.get(key, {"untagged"})) 
            # Storing the (dstport, protocol, tag) tuple
            port_proto_tag.append((dstport, protocol, tag)) 
            # Incrementing the count for this tag
            tags_count[tag] += 1  
            # Storing the (dstport, protocol) combination
            port_proto_combo.append((dstport, protocol)) 

    return port_proto_tag, tags_count, port_proto_combo


def write_output(tag_count, port_proto_count, output_file):
    """
    Write the results of the log processing to an output CSV file.
    Args:
        tags_count (dict): A dictionary with tags as keys and their counts as values.
        port_proto_count (list): A list of tuples (dstport, protocol, count) for each combination.
        output_file (str): Path to the output file where results will be written.
    """
    with open(output_file, 'w', newline='') as of:
        writer = csv.writer(of)

        # Write the "Tag Counts:" heading
        writer.writerow(["Tag Counts:"])
        writer.writerow(["Tag", "Count"])
        
        # Write the tag_count data
        for tag, count in tag_count.items():
            writer.writerow([tag, count])
        
        # Add a blank line for separation
        writer.writerow([])

        # Write the "Port/Protocol Combination Counts:" heading
        writer.writerow(["Port/Protocol Combination Counts:"])
        writer.writerow(["Port", "Protocol", "Count"])

        # Write the port_proto_count data
        for entry in port_proto_count:
            writer.writerow(entry)


def main():
    """
    Driver function to handle loading, processing, and writing of flow logs data.
    csv file from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        to map protocol Iana numbers to actual strings. Ex: map 6 -> TCP"""

    parser = argparse.ArgumentParser(description="Process file paths based on the root directory")
    parser.add_argument('--test', type=str, default="", help='Root directory for file paths')
    args = parser.parse_args()
    root = args.test

    # Default paths for the files
    lookup_file = 'Lookup/lookup_table.csv'
    flow_file = 'FlowLogsInput/flow_logs.csv'
    output_file = os.path.join(os.getcwd(), 'Output/output.txt')

    # Update the file paths based on the value of root(if we are running tests)
    if root != "":
        lookup_file = f'{root}/Lookup/lookup_table.csv'
        flow_file = f'{root}/FlowLogsInput/flow_logs.csv'
        output_file = os.path.join(os.getcwd(), f'{root}/Output/output.txt')
      
    # Loading mappings and lookup table  
    protocol_file = 'protocol_numbers_mapping.csv' 
    protocol_map = load_protocol_mapping(protocol_file)
    lookup_table = load_lookup_table(lookup_file)
    
    # Processing the flow logs
    port_proto_tag, tags_count, port_proto_combo = process_flow_logs(flow_file, lookup_table, protocol_map)

    """ Example custom format: dstport at index 8, protocol_number at index 9, uncomment below code for custom format
           
    custom_format = [('dstport', 8), ('protocol_number', 9)] 

    port_proto_tag, tags_count, port_proto_combo = process_flow_logs_extended(flow_file=flow_file,
                                                                            lookup_table=lookup_table,
                                                                            protocol_map=protocol_map,
                                                                            log_format=custom_format)
    """

    # Counting occurrences of each (dstport, protocol) combination  
    port_proto_combo_counts = Counter(port_proto_combo)
    port_proto_count = [(dstport, protocol, count) for (dstport, protocol), count in port_proto_combo_counts.items()]
    
    # Writing results to the output file
    write_output(tags_count, port_proto_count, output_file)

      
    print(f"Output successfully written to: {output_file}")

if __name__ == "__main__":
    main()
