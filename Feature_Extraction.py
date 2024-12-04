import urllib.parse
from urllib.parse import unquote_plus
from xml.etree import ElementTree as ET
import base64
import csv
import os

log_path = r"C:\Users\91637\Downloads\allgood.log"
output_csv_path = r"C:\Users\91637\Downloads\all_good.csv"  
class_flag = "good"


badwords = [
    'insert', 'INSERT', 
    'update', 'UPDATE', 
    'delete', 'DELETE', 
    'drop', 'DROP', 
    'benchmark', 'BENCHMARK', 
    'exec', 'EXEC', 
    'sleep', 'SLEEP', 
    'uid', 'UID', 
    'select', 'SELECT', 
    'waitfor', 'WAITFOR', 
    'delay', 'DELAY', 
    'system', 'SYSTEM', 
    'union', 'UNION', 
    'order by', 'ORDER BY', 
    'group by', 'GROUP BY'
]




# Function to parse the log file
def parse_log(log_path):
    '''
    Parses a Burp log file and returns a dictionary of request and response pairs.
    result = {'GET /page.php...':'200 OK HTTP / 1.1....', '': '', .....}
    '''
    result = {}
    try:
        with open(log_path): pass
    except IOError:
        print("[+] Error!!! ", log_path, "doesn't exist..")
        exit()

    try:
        tree = ET.parse(log_path)
    except Exception as e:
        print('[+] Oops..! Please ensure binary data is not present in the log, like raw image dumps, etc.')
        exit()

    root = tree.getroot()
    for reqs in root.findall('item'):
        raw_req = reqs.find('request').text
        raw_req = urllib.parse.unquote(raw_req)  # Decode URL-encoded characters
        raw_resp = reqs.find('response').text
        result[raw_req] = raw_resp

    return result

# Function to parse raw HTTP request
def parseRawHTTPReq(rawreq):   
    try:
        raw = rawreq.decode('utf8')
    except Exception as e:
        print("Decode error:", e)
        return {}, None, None, None

    headers = {}
    if '\r\n\r\n' in raw:
        head, body = raw.split('\r\n\r\n', 1)
    else:
        head, body = raw.split('\n\n', 1) if '\n\n' in raw else (raw, "")

    lines = head.splitlines()
    try:
        request_line = lines[0]
        method, path, _ = request_line.split(' ', 2)
    except ValueError:
        print("Failed to parse request line:", lines[0])
        return {}, None, None, None

    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value

    return headers, method, body, path

# Function to extract features
def ExtractFeatures(method, path_enc, body_enc, headers):
    badwords_count = 0
    path = unquote_plus(path_enc)
    body = urllib.parse.unquote(body_enc)
    single_q = path.count("'") + body.count("'")
    double_q = path.count("\"") + body.count("\"")
    dashes = path.count("--") + body.count("--")
    braces = path.count("(") + body.count("(")
    spaces = path.count(" ") + body.count(" ")
    
    # Count badwords in path and body
    for word in badwords:
        badwords_count += path.lower().count(word) + body.lower().count(word)

    # Count badwords in headers
    for header in headers:
        badwords_count += headers[header].lower().count(word)  # Count badwords in header values

    return [method, path_enc.encode('utf-8').strip(), body_enc.encode('utf-8').strip(), 
            single_q, double_q, dashes, braces, spaces, badwords_count]

# Initialize the CSV file and write the header
with open(output_csv_path, "w", newline='', encoding='utf-8') as f:
    c = csv.writer(f)
    c.writerow(["method", "path", "body", "single_q", "double_q", "dashes", "braces", "spaces", "badwords", "class"])

# Parse the log file and iterate through each request
result = parse_log(log_path)

for items in result:
    raaw = base64.b64decode(items)  # Decode the base64 encoded request
    headers, method, body, path = parseRawHTTPReq(raaw)
    if method and path:  # Ensure the request has valid data
        list1 = ExtractFeatures(method, path, body, headers) + [class_flag]  # Append class_flag
        with open(output_csv_path, "a", newline='', encoding='utf-8') as f:  # Append to the CSV
            c = csv.writer(f)
            c.writerow(list1)  # Write row

print("Processing completed. The CSV file is saved at:", output_csv_path)
