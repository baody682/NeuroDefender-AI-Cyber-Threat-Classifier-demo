import os
import time
import subprocess
import pandas as pd
import requests
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import argparse

# --- Configuration ---
PCAP_INPUT_DIR = "C:\\captures"
CICFLOWMETER_PATH = "C:\\Users\\mahbo\\Downloads\\CICFlowMeter-master\\CICFlowMeter-master\\build\\libs\\CICFlowMeter-all-4.0.jar"
OUTPUT_CSV_DIR = "C:\\temp_cic_output"
FLASK_API_ENDPOINT = "http://127.0.0.1:5000/api/process_cicflow_data"

# Changed logging level to DEBUG for more verbose output during debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

os.makedirs(OUTPUT_CSV_DIR, exist_ok=True)
logger.info(f"Monitoring PCAP files in: {PCAP_INPUT_DIR}")
logger.info(f"CICFlowMeter output will be saved to: {OUTPUT_CSV_DIR}")
logger.info(f"Flask API endpoint: {FLASK_API_ENDPOINT}")

# IMPORTANT: This list MUST match the EXACT list of features your model was trained on, in the correct order,
# without the 'label' column.
EXPECTED_COLUMNS_MODEL = [
    'destination_port',
    'flow_duration',
    'total_fwd_packets',
    'total_backward_packets',
    'total_length_of_fwd_packets',
    'total_length_of_bwd_packets',
    'fwd_packet_length_max',
    'fwd_packet_length_min',
    'fwd_packet_length_mean',
    'fwd_packet_length_std',
    'bwd_packet_length_max',
    'bwd_packet_length_min',
    'bwd_packet_length_mean',
    'bwd_packet_length_std',
    'flow_bytes_s',
    'flow_packets_s',
    'flow_iat_mean',
    'flow_iat_std',
    'flow_iat_max',
    'flow_iat_min',
    'fwd_iat_total',
    'fwd_iat_mean',
    'fwd_iat_std',
    'fwd_iat_max',
    'fwd_iat_min',
    'bwd_iat_total',
    'bwd_iat_mean',
    'bwd_iat_std',
    'bwd_iat_max',
    'bwd_iat_min',
    'fwd_psh_flags',
    'fwd_urg_flags',
    'fwd_header_length',
    'bwd_header_length',
    'fwd_packets_s',
    'bwd_packets_s',
    'min_packet_length',
    'max_packet_length',
    'packet_length_mean',
    'packet_length_std',
    'packet_length_variance',
    'fin_flag_count',
    'syn_flag_count',
    'rst_flag_count',
    'psh_flag_count',
    'ack_flag_count',
    'urg_flag_count',
    'cwe_flag_count',
    'ece_flag_count',
    'down_up_ratio',
    'average_packet_size',
    'avg_fwd_segment_size',
    'avg_bwd_segment_size',
    'subflow_fwd_packets',
    'subflow_fwd_bytes',
    'subflow_bwd_packets',
    'subflow_bwd_bytes',
    'init_win_bytes_forward',
    'init_win_bytes_backward',
    'act_data_pkt_fwd',
    'min_seg_size_forward',
    'active_mean',
    'active_std',
    'active_max',
    'active_min',
    'idle_mean',
    'idle_std',
    'idle_max',
    'idle_min'
]


CICFLOWMETER_COLUMN_ALIASES = {
    # Flask name: [CICFlowMeter's potential raw names in CSV (case-insensitive, cleaned)]
    'flow_duration': ['Flow Duration'],
    'total_fwd_packets': ['Total Fwd Packet'],
    'total_backward_packets': ['Total Bwd packets'],
    'total_length_of_fwd_packets': ['Total Length of Fwd Packet'],
    'total_length_of_bwd_packets': ['Total Length of Bwd Packet'],
    'fwd_packet_length_max': ['Fwd Packet Length Max'],
    'fwd_packet_length_min': ['Fwd Packet Length Min'],
    'fwd_packet_length_mean': ['Fwd Packet Length Mean'],
    'fwd_packet_length_std': ['Fwd Packet Length Std'],
    'bwd_packet_length_max': ['Bwd Packet Length Max'],
    'bwd_packet_length_min': ['Bwd Packet Length Min'],
    'bwd_packet_length_mean': ['Bwd Packet Length Mean'],
    'bwd_packet_length_std': ['Bwd Packet Length Std'],
    'flow_bytes_s': ['Flow Bytes/s', 'Flow Bytes/s'], # CICFlowMeter's actual name
    'flow_packets_s': ['Flow Packets/s'],
    'flow_iat_mean': ['Flow IAT Mean'],
    'flow_iat_std': ['Flow IAT Std'],
    'flow_iat_max': ['Flow IAT Max'],
    'flow_iat_min': ['Flow IAT Min'],
    'fwd_iat_total': ['Fwd IAT Total'],
    'fwd_iat_mean': ['Fwd IAT Mean'],
    'fwd_iat_std': ['Fwd IAT Std'],
    'fwd_iat_max': ['Fwd IAT Max'],
    'fwd_iat_min': ['Fwd IAT Min'],
    'bwd_iat_total': ['Bwd IAT Total'],
    'bwd_iat_mean': ['Bwd IAT Mean'],
    'bwd_iat_std': ['Bwd IAT Std'],
    'bwd_iat_max': ['Bwd IAT Max'],
    'bwd_iat_min': ['Bwd IAT Min'],
    'fwd_psh_flags': ['Fwd PSH Flags'],
    'fwd_urg_flags': ['Fwd URG Flags'],
    'fwd_header_length': ['Fwd Header Length'],
    'bwd_header_length': ['Bwd Header Length'],
    'fwd_packets_s': ['Fwd Packets/s'],
    'bwd_packets_s': ['Bwd Packets/s'],
    'min_packet_length': ['Packet Length Min'],
    'max_packet_length': ['Packet Length Max'],
    'packet_length_mean': ['Packet Length Mean'],
    'packet_length_std': ['Packet Length Std'],
    'packet_length_variance': ['Packet Length Variance'],
    'fin_flag_count': ['FIN Flag Count'],
    'syn_flag_count': ['SYN Flag Count'],
    'rst_flag_count': ['RST Flag Count'],
    'psh_flag_count': ['PSH Flag Count'],
    'ack_flag_count': ['ACK Flag Count'],
    'urg_flag_count': ['URG Flag Count'],
    'cwe_flag_count': ['CWR Flag Count'], # 'CWR Flag Count' in CICFlowMeter output
    'ece_flag_count': ['ECE Flag Count'],
    'down_up_ratio': ['Down/Up Ratio'],
    'average_packet_size': ['Average Packet Size'],
    'avg_fwd_segment_size': ['Fwd Segment Size Avg'],
    'avg_bwd_segment_size': ['Bwd Segment Size Avg'],
    'subflow_fwd_packets': ['Subflow Fwd Packets'],
    'subflow_fwd_bytes': ['Subflow Fwd Bytes'],
    'subflow_bwd_packets': ['Subflow Bwd Packets'],
    'subflow_bwd_bytes': ['Subflow Bwd Bytes'],
    'init_win_bytes_forward': ['FWD Init Win Bytes'],
    'init_win_bytes_backward': ['Bwd Init Win Bytes'],
    'act_data_pkt_fwd': ['Fwd Act Data Pkts'],
    'min_seg_size_forward': ['Fwd Seg Size Min'],
    'active_mean': ['Active Mean'],
    'active_std': ['Active Std'],
    'active_max': ['Active Max'],
    'active_min': ['Active Min'],
    'idle_mean': ['Idle Mean'],
    'idle_std': ['Idle Std'],
    'idle_max': ['Idle Max'],
    'idle_min': ['Idle Min'],
    'destination_port': ['Dst Port'],
}

def process_pcap_with_cicflowmeter(pcap_filepath):
    pcap_filename = os.path.basename(pcap_filepath)
    output_csv_filename_prefix = os.path.splitext(pcap_filename)[0] # Base name for matching
    
    command = [
        'java',
        '-Djava.library.path=C:\\Program Files\\Npcap',
        '-jar',
        CICFLOWMETER_PATH,
        pcap_filepath,
        OUTPUT_CSV_DIR
    ]

    logger.info(f"Running CICFlowMeter on: {pcap_filepath}")
    logger.info(f"Command: {' '.join(command)}")

    try:
        # Run CICFlowMeter
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
        logger.info(f"CICFlowMeter stdout:\n{result.stdout}")
        if result.stderr:
            logger.warning(f"CICFlowMeter stderr:\n{result.stderr}")

        # CICFlowMeter appends timestamp and _Flow to the output filename
        # We need to find the most recently modified CSV file matching the prefix
        time.sleep(1) # Give a moment for file system to update
        generated_csv_files = [
            os.path.join(OUTPUT_CSV_DIR, f)
            for f in os.listdir(OUTPUT_CSV_DIR)
            if f.startswith(output_csv_filename_prefix) and f.endswith(".csv") and "_Flow.csv" in f # Ensure it's a flow file
        ]
        
        if generated_csv_files:
            # Sort by modification time to get the latest one
            actual_output_csv_filepath = max(generated_csv_files, key=os.path.getmtime)
            logger.info(f"CICFlowMeter output saved to: {actual_output_csv_filepath}")
            return actual_output_csv_filepath
        else:
            logger.error(f"No CSV file generated by CICFlowMeter for {pcap_filename} in {OUTPUT_CSV_DIR}. Listing contents: {os.listdir(OUTPUT_CSV_DIR)}")
            return None

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running CICFlowMeter on {pcap_filepath}: {e}", exc_info=True)
        logger.error(f"STDOUT: {e.stdout}")
        logger.error(f"STDERR: {e.stderr}")
        return None
    except FileNotFoundError:
        logger.error(f"CICFlowMeter.jar not found at {CICFLOWMETER_PATH}. Please check the path.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during CICFlowMeter execution: {e}", exc_info=True)
        return None

def standardize_columns_script(df):
    logger.debug(f"Initial columns in standardize_columns_script: {df.columns.tolist()}")

    # 1. Clean current DataFrame columns
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_").str.replace("/", "_").str.replace(".", "_")
    logger.debug(f"Columns after initial cleaning in script: {df.columns.tolist()}")
    
    # 2. Create a mapping from cleaned_csv_column_name to expected_model_column_name
    column_mapping = {}
    for expected_col, aliases in CICFLOWMETER_COLUMN_ALIASES.items():
        # Check the exact expected_col name first (if it's already clean)
        if expected_col in df.columns and expected_col not in column_mapping.values():
            column_mapping[expected_col] = expected_col
            continue
        
        # Then check aliases
        for alias in aliases:
            cleaned_alias = alias.strip().lower().replace(" ", "_").replace("/", "_").replace(".", "_")
            if cleaned_alias in df.columns and cleaned_alias not in column_mapping.keys(): # Ensure not to overwrite an existing mapping
                column_mapping[cleaned_alias] = expected_col
                logger.debug(f"Mapping '{cleaned_alias}' to '{expected_col}'")
                break # Stop after finding the first match for this expected_col
    
    # 3. Rename columns in the DataFrame based on the mapping
    # Only rename if the column exists in the mapping keys
    df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)
    logger.debug(f"Columns after renaming by script: {df.columns.tolist()}")

    # 4. Add missing columns and ensure correct data types
    for col in EXPECTED_COLUMNS_MODEL:
        if col not in df.columns:
            df[col] = 0.0 # Add missing columns with default value 0.0
            logger.debug(f"Added missing model column '{col}' with 0.0 in script.")
        else:
            # Ensure numeric type, coerce errors will turn non-numeric into NaN, then fillna(0.0)
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Fill any NaNs created by 'coerce' and handle inf values
    df = df.replace([pd.NA, pd.NaT, None], 0.0).fillna(0.0).replace([float('inf'), -float('inf')], 0.0)
    
    # 5. Select and reorder columns to match EXPECTED_COLUMNS_MODEL
    # Only include columns that are actually in EXPECTED_COLUMNS_MODEL
    final_df = df[EXPECTED_COLUMNS_MODEL].copy()
    
    logger.debug(f"Final columns to send to Flask after standardization: {final_df.columns.tolist()}")
    return final_df

def send_data_to_flask(flows_df):
    if flows_df.empty:
        logger.info("No valid flows to send to Flask.")
        return
    flows_data = flows_df.to_dict(orient='records')
    payload = {"flows": flows_data}
    try:
        response = requests.post(FLASK_API_ENDPOINT, json=payload, timeout=10)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        logger.info(f"Data sent to Flask successfully. Processed flows: {response.json().get('processed_flows', 0)}, Anomalies: {response.json().get('anomalies_detected', 0)}")
    except requests.exceptions.Timeout:
        logger.error(f"Request to Flask API timed out after 10 seconds. Is Flask app running at {FLASK_API_ENDPOINT}?")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Could not connect to Flask API at {FLASK_API_ENDPOINT}. Is the Flask app running and accessible?", exc_info=True)
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error sending data to Flask: {e.response.status_code} - {e.response.text}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending data to Flask: {e}", exc_info=True)

class PcapFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.pcap'):
            logger.info(f"New PCAP file detected: {event.src_path}")
            # Wait for file to be fully written
            time.sleep(2) 
            while True:
                try:
                    with open(event.src_path, 'rb') as f:
                        f.read(1) # Try reading a byte to check if file is accessible
                    break
                except IOError:
                    logger.warning(f"File {event.src_path} is still being written to, waiting...")
                    time.sleep(2)
            
            csv_output_path = process_pcap_with_cicflowmeter(event.src_path)
            if csv_output_path and os.path.exists(csv_output_path):
                try:
                    # Give CICFlowMeter a moment to truly finish writing the CSV
                    time.sleep(1) 
                    df = pd.read_csv(csv_output_path)
                    logger.info(f"Loaded {len(df)} rows from {csv_output_path}")

                    # Drop 'Label' column if it exists, as it's not a feature for prediction
                    if 'Label' in df.columns:
                        df = df.drop(columns=['Label'], errors='ignore')
                    elif 'label' in df.columns:
                        df = df.drop(columns=['label'], errors='ignore')
                    
                    processed_df = standardize_columns_script(df)
                    send_data_to_flask(processed_df)
                except pd.errors.EmptyDataError:
                    logger.warning(f"CSV file {csv_output_path} is empty or contains no data after CICFlowMeter processing.")
                except Exception as e:
                    logger.error(f"Error processing CSV {csv_output_path}: {e}", exc_info=True)
            else:
                logger.error(f"Failed to get CSV output path for {event.src_path}.")
            logger.info(f"Finished processing PCAP file: {event.src_path}") # Added log
                
def start_monitoring():
    event_handler = PcapFileHandler()
    observer = Observer()
    observer.schedule(event_handler, PCAP_INPUT_DIR, recursive=False)
    observer.start()
    logger.info(f"Started monitoring {PCAP_INPUT_DIR} for new .pcap files. Observer active.") # Added log
    try:
        while True:
            time.sleep(1)
            logger.debug("Monitoring loop heartbeat...") # Added heartbeat log for main thread
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt detected. Stopping observer.") # Added log
        observer.stop()
    observer.join()
    logger.info("Monitoring stopped gracefully.") # Added log

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process PCAP files with CICFlowMeter or monitor a directory.")
    parser.add_argument('--input', type=str, help='Path to a single PCAP file to process.')
    parser.add_argument('--output', type=str, help='Path for the output CSV file.')
    parser.add_argument('--monitor', action='store_true', help='Start monitoring the PCAP_INPUT_DIR for new files.')

    args = parser.parse_args()

    if args.input and args.output:
        logger.info(f"Command line arguments detected. Processing single PCAP file: {args.input}")
        # Call CICFlowMeter directly for the specified input file
        csv_output_path = process_pcap_with_cicflowmeter(args.input)
        if csv_output_path and os.path.exists(csv_output_path):
            try:
                # Give CICFlowMeter a moment to truly finish writing the CSV
                time.sleep(1)
                df = pd.read_csv(csv_output_path)
                logger.info(f"Loaded {len(df)} rows from {csv_output_path}")

                if 'Label' in df.columns:
                    df = df.drop(columns=['Label'], errors='ignore')
                elif 'label' in df.columns:
                    df = df.drop(columns=['label'], errors='ignore')

                processed_df = standardize_columns_script(df)
                
                output_dir = os.path.dirname(args.output)
                os.makedirs(output_dir, exist_ok=True)
                processed_df.to_csv(args.output, index=False)
                logger.info(f"Processed data saved to: {args.output}")

                # If you still want to send data to Flask API for live analysis, you can call it here:
                # send_data_to_flask(processed_df)
                
            except pd.errors.EmptyDataError:
                logger.warning(f"CSV file {csv_output_path} is empty or contains no data after CICFlowMeter processing.")
            except Exception as e:
                logger.error(f"Error processing CSV {csv_output_path}: {e}", exc_info=True)
        else:
            logger.error(f"Failed to get CSV output path for {args.input}.")
        logger.info(f"Finished single file processing for: {args.input}")

    elif args.monitor:
        logger.info("Monitoring mode activated.")
        start_monitoring() # This will run the observer for continuous monitoring
    else:
        # Default behavior if no arguments are provided or invalid combination
        logger.warning("No --input/--output specified, or --monitor not set. Starting monitoring mode by default.")
        start_monitoring()