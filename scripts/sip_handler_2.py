import os
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from OpenSIPS import *
from nats.aio.client import Client as NATS
from nats.aio.errors import ErrTimeout
import asyncio

class Test:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.nats_server = "nats://localhost:4222"  # Update  NATS server
        self.nats_subject = "opensips_request"      # Update  NATS subject
        self.loop = asyncio.get_event_loop()
        LM_ERR('Python script initialized.\n')

    def child_init(self, y):
        LM_ERR('test.child_init(%d)\n' % y)
        return 0

    def handler(self, msg):
        # Start measuring the total handler execution time
        start_time = time.time()

        # Extract Method, RURI, and headers
        method = msg.Method
        ruri = msg.RURI
        
        # Time parsing headers
        parse_start = time.time()

        from_header = msg.getHeader('from')
        to_header = msg.getHeader('to')

        if from_header is None or to_header is None:
            LM_ERR("Error: Missing 'from' or 'to' headers.")
            return

        # Parse headers
        from_uri = self.parse_sip_uri(from_header)
        to_uri = self.parse_sip_uri(to_header)

        # Extract additional headers
        call_id = msg.getHeader('call-id')
        cseq = msg.getHeader('cseq')
        contact = msg.getHeader('contact')
        diversion = msg.getHeader('diversion')
        p_asserted_identity = msg.getHeader('p-asserted-identity')
        p_charge_info = msg.getHeader('p-charge-info')
        max_forwards = msg.getHeader('max-forwards')
        via = msg.getHeader('via')

        contact_parsed = self.parse_sip_uri(contact) if contact else None
        via_parsed = self.parse_via_header(via) if via else None

        # Log each header parsed
        LM_ERR(f"Method: {method}")
        LM_ERR(f"RURI: {ruri}")
        LM_ERR(f"From Header: {from_header}")
        LM_ERR(f"From Parsed: {from_uri}")
        LM_ERR(f"To Header: {to_header}")
        LM_ERR(f"To Parsed: {to_uri}")
        LM_ERR(f"Call-ID: {call_id}")
        LM_ERR(f"CSeq: {cseq}")
        LM_ERR(f"Contact: {contact}")
        LM_ERR(f"Contact Parsed: {contact_parsed}")
        LM_ERR(f"Diversion: {diversion}")
        LM_ERR(f"P-Asserted-Identity: {p_asserted_identity}")
        LM_ERR(f"P-Charge-Info: {p_charge_info}")
        LM_ERR(f"Max-Forwards: {max_forwards}")
        LM_ERR(f"Via: {via}")
        LM_ERR(f"Via Parsed: {via_parsed}")

        # Handle diversion logic
        diversion_parsed = self.parse_diversion_header(diversion) if diversion else None
        if diversion_parsed:
            LM_ERR(f"Diversion Parsed: {diversion_parsed}")
        else:
            LM_ERR("No valid diversion header present.")

        header_data = {
            'Method': method,
            'RURI': ruri,
            'From': from_header,
            'To': to_header,
            'From User Part': from_uri["user"],
            'From Host Part': from_uri["host"],
            'From Port Part': from_uri["port"],
            'To User Part': to_uri["user"],
            'To Host Part': to_uri["host"],
            'To Port Part': to_uri["port"],
            'Call-ID': call_id,
            'CSeq': cseq,
            'Contact': contact,
            'Diversion': diversion,
            'P-Asserted-Identity': p_asserted_identity,
            'P-Charge-Info': p_charge_info,
            'Max-Forwards': max_forwards,
            'Via': via,
            'Contact User Part': contact_parsed["user"] if contact_parsed else None,
            'Contact Host Part': contact_parsed["host"] if contact_parsed else None,
            'Contact Port Part': contact_parsed["port"] if contact_parsed else None,
            'Via Parsed': via_parsed,
            'Diversion Parsed': diversion_parsed,
            'Processing Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start_time))
        }

        parse_end = time.time()
        LM_ERR(f"Header parsing time: {(parse_end - parse_start) * 1000:.2f} ms")

        # Save the parsed data using the executor
        save_start = time.time()
        self.executor.submit(self.save_to_json, header_data)
        save_end = time.time()
        LM_ERR(f"Log saving time: {(save_end - save_start) * 1000:.2f} ms")

        # NATS integration
        nats_response_code = self.loop.run_until_complete(self.send_request_to_nats(header_data))

        # Apply the response time and introduce a delay of 50ms before sending the response back
        delay_start = time.time()
        self.delay_response(50)
        delay_end = time.time()

        # Calculate the time taken to process and add the delay before sending the response
        response_time_ms = (delay_end - start_time + (delay_end - delay_start)) * 1000

        if nats_response_code == "1":
            LM_ERR(f"Match found for NATS response code {nats_response_code}, returning 1 (redirect).")
            LM_ERR(f"Total time taken to send response back to OpenSIPS, including delay: {response_time_ms:.2f} ms")
            return 1
        else:
            LM_ERR(f"No match found for NATS response code {nats_response_code}, returning 0 (forbidden).")
            LM_ERR(f"Total time taken to send response back to OpenSIPS, including delay: {response_time_ms:.2f} ms")
            return 0

    async def send_request_to_nats(self, header_data):
        """Send data to NATS and retrieve the response."""
        try:
            nc = NATS()
            await nc.connect(servers=[self.nats_server])
            LM_ERR(f"Connected to NATS: {self.nats_server}")

            # Serialize header data as JSON
            payload = json.dumps(header_data)

            # Publish the request and wait for a reply
            response = await nc.request(self.nats_subject, payload.encode(), timeout=1)

            # Parse the response from NATS
            response_data = response.data.decode()
            LM_ERR(f"NATS Response: {response_data}")

            # Assuming NATS response is a simple response code like "1" or "0"
            await nc.close()
            return response_data.strip()
        except ErrTimeout:
            LM_ERR("Error: NATS request timed out.")
            return "0"
        except Exception as e:
            LM_ERR(f"Error in NATS communication: {str(e)}")
            return "0"

    def parse_sip_uri(self, header):
        header = header.strip('<>')
        pattern = r'sip:(?P<user>[^@]+)@(?P<host>[^:;]+)(?::(?P<port>\d+))?(?:;(.*))?'
        match = re.search(pattern, header)
        if match:
            parameters = match.group(4) if match.group(4) else ''
            parsed = {
                'user': match.group('user'),
                'host': match.group('host').strip('>'),
                'port': match.group('port') if match.group('port') else None,
                'parameters': parameters
            }
            LM_ERR(f"Parsed SIP URI: {parsed}")
            return parsed
        else:
            LM_ERR(f"Error: Unable to parse URI from header: {header}")
            return {'user': None, 'host': None, 'port': None, 'parameters': None}

    def parse_via_header(self, header):
        header = header.strip('<>')
        pattern = r'([A-Za-z0-9\-]+)/([A-Za-z]+)\s+([^;]+)(?:;.*?branch=(z9hG4bK[^;]+))?(?:;(.*))?'
        match = re.search(pattern, header)
        if match:
            parameters = match.group(5) if match.group(5) else ''
            parsed = {
                'host': match.group(3).split(':')[0],
                'port': match.group(3).split(':')[1] if ':' in match.group(3) else None,
                'branch': match.group(4),
                'parameters': parameters
            }
            LM_ERR(f"Parsed Via Header: {parsed}")
            return parsed
        else:
            LM_ERR(f"Error: Unable to parse Via header: {header}")
            return {'host': None, 'port': None, 'branch': None, 'parameters': None}

    def parse_diversion_header(self, header):
        header = header.strip('<>')
        pattern = r'sip:(?P<user>[^@]+)@(?P<host>[^:;]+)(?::(?P<port>\d+))?(?:;(.*))?'
        match = re.search(pattern, header)
        if match:
            parameters = match.group(4) if match.group(4) else ''
            parsed = {
                'user': match.group('user'),
                'host': match.group('host'),
                'port': match.group('port') if match.group('port') else None,
                'parameters': parameters
            }
            LM_ERR(f"Parsed Diversion Header: {parsed}")
            return parsed
        else:
            LM_ERR(f"Error: Unable to parse diversion header: {header}")
            return None

    def save_to_json(self, data):
        file_path = '/usr/local/etc/opensips/python/save/headers.json'
        directory = os.path.dirname(file_path)

        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            LM_ERR(f"Directory created: {directory}")

        existing_data = []
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as json_file:
                    content = json_file.read()
                    if content.strip():
                        existing_data = json.loads(content)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                LM_ERR(f"Error reading JSON data: {e}")

        if not isinstance(existing_data, list):
            existing_data = []

        existing_data.append(data)

        try:
            with open(file_path, 'w') as json_file:
                json.dump(existing_data, json_file, indent=4)
                LM_ERR(f"Headers saved to {file_path}")
        except Exception as e:
            LM_ERR(f"Error saving JSON: {e}")

    def delay_response(self, delay_ms):
        time.sleep(delay_ms / 1000.0)

def mod_init():
    LM_ERR('Initializing Python module...\n')
    return Test()
