'''

Script for log analysis

'''
import sys
import multiprocessing
import re
import heapq,csv
from  ipSort  import trieHashmap, lastnode, add, sort
import argparse
import os

class log_file():

    def __init__(self, path, output_path):
        self.path = path
        self.output_path = output_path

    
    def find_max_chunk(self, chunk):
        max_key = None
        max_val = 0
    
        for key, value in chunk.items():
            if value > max_val:
                max_val = value
                max_key = key
        return max_key, max_val
            
            # Function to split the dictionary into chunks for multiprocessing

    def chunkify(self, data, num_chunks):
            # Split the dictionary into chunks
        chunk_size = len(data) // num_chunks
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(dict(list(data.items())[i:i+chunk_size]))
        return chunks
            
    def sort(self):
        """
        Function to implement the sort of ip addresses
        """
        main = trieHashmap()
        # h2_ = {}
        with open(self.path, 'r') as file:
            for line in file:
                regex = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
        # Match the line (after stripping any leading/trailing whitespace)
                match = re.match(regex, line.strip())
                if match:
                    ip = match.group()  # Extract matched IP address
                    # if ip in h2_.keys():
                    #     h2_[ip] += 1
                    # else:
                    #     h2_[ip] = 1
                    add(main, ip)

        sort(main, self.output_path)

    def most_acess_dir(self, num_processes = 1):
        """

        To implement for acessed directory,
        uses hashmap to find the frquency of end point

        hashmap has key, value data where key is endpoint and value is its frequency
        And using multi threading to find maximum
        """
    

        regex = r'\b(?:POST|GET|DELETE|PATCH)\s+(/\S+)'

        hashmap = {} # hashmap

        with open(self.path, 'r') as file:
            for line in file:
                match = re.search(regex, line)
                if match:
                # Extract the endpoint
                    endpoint = match.group(1)
                # Update the count in the hashmap
                    if endpoint in hashmap.keys():
                        hashmap[endpoint] += 1
                    else:
                        hashmap[endpoint] = 1


        max_access = 0
        end_point_max = None


        
        if num_processes == 1:
            for counter, key in enumerate(hashmap):
                if hashmap[key] >  max_access:
                    max_access = hashmap[key]
                    end_point_max = key
        else:
            '''
            Apply the multithreading
            '''
            # Function to find the max of a part of the dictionary

        # Create a Pool of workers
            chunks = self.chunkify(hashmap, num_processes)
            with multiprocessing.Pool(processes=num_processes) as pool:
                results = pool.map(self.find_max_chunk, chunks)
        
        # Find the max result among all chunks

            for key, value in results:
                if value > max_access:
                    max_access = value
                    end_point_max = key
        
        print("")
        print("Most Frequently Accessed Endpoint:")
        print(f"{end_point_max}   (Accessed {max_access} times)")

        with open(self.output_path, 'w', newline='') as log_analysis_file:
            writer = csv.writer(log_analysis_file, delimiter=",")
            writer.writerow(["Endpoint, Access Count"])
            writer.writerow([f"{end_point_max}   (Accessed {max_access} times)"])
            
        # write into the file
                 
    def cyber_analysis(self, threshold=10, threshold2=4):

        '''
            Detecting 401, 400, 429, 404
            and most frequently acessed urls of 200 code (login)
            and first failed threshold2 times to login and got accessed 
        '''

        most_access = {} # \login - 200 success
        login_failed = {}  
        login_sucess_after_failed = {}
        unauthorized_success = {}

        with open(self.path, 'r') as file:
            
            # regex expression to acess the error codes from the line

            log_line = '203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"'

            # Regex to capture IP address, access point, and HTTP status code
            regex = r'(?P<IP_address>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?:POST|GET|PUT|PATCH) (?P<access_point>.*?) HTTP/.*?" (?P<code>\d+)'
 
            match = re.match(regex, log_line)

            if match:
                IP_address = match.group("IP_address")
                access_point = match.group("access_point")
                code = match.group("code")

                if code == 200 and access_point == r"\login":

                    if IP_address not in login_sucess_after_failed.keys():

                        if IP_address in login_failed.keys() :
                            if login_failed[IP_address] > threshold2:
                        # delete key in the login_failed
                                del login_failed[IP_address]
                                login_sucess_after_failed[IP_address] = f"Success after login failed {threshold2}"

                        else:
                            most_access[IP_address] = 1

                elif code == "404" or code == "401" or code == "400" or code ==  "429" or code == "404":
                    if IP_address in login_failed.keys():
                        login_failed[IP_address]  += 1
                    else:
                        login_failed[IP_address] = 1
                
                elif code == "200" and IP_address not in most_access.keys():
                    # Considering the IP addresses who didn't login but acess other end points
                    unauthorized_success[IP_address] = 1

            def mean(h):
                c = 0
                x = 1
                for i, value in enumerate(h):
                    c += h[value]
                    x = i + 1
                return c//x
            # finding average access
      
          #  login failed URL's
            with open(self.output_path, 'w', newline='') as log_analysis_file:
                writer = csv.writer(log_analysis_file, delimiter=",")
                writer.writerow(["Endpoint, Access Count"])
               

                for ip_a, count in login_failed.items():
                    if count > threshold :
                        print(f"{ip_a :<20} {count}")
                        writer.writerow([ip_a, count])

         
          #  most frequency accessed URL's
                threshold3 = mean(most_access)
                for ip_a, count in most_access.items():
                    if count > threshold3 :
                        print(f"{ip_a :<20} {count}")
                        writer.writerow([ip_a, count])
                    
            
          #  Suspicious URL's which have login failed threadhold2 times, but succed after it
                for ip_a , _ in login_sucess_after_failed.items():
                    print(f"{ip_a :<20} Malicious login")
                    writer.writerow([ip_a, count])

                for ip_a, _ in unauthorized_success.items():
                    print(f"{ip_a :<20} Malicious Access")
                    writer.writerow([ip_a, count])

                
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Python file parser with various operations.")
    parser.add_argument("-sort", action="store_true", help="IP address request count order")
    parser.add_argument("-m_a", action="store_true", help="most access end point")
    parser.add_argument("-sus", action="store_true", help="Suspicious activities")
    parser.add_argument("--InputFilepath", required=True, help="Path to the input file.")
    parser.add_argument("-o", "--OutputFilepathDirectory", required=True, help="Path to the output directory.")

    args = parser.parse_args()

    input_filepath = args.InputFilepath
    output_directory = args.OutputFilepathDirectory

    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Generate the output file path
    output_filepath = os.path.join(output_directory, os.path.basename('log_analysis_results.csv'))

    if os.path.exists(input_filepath):

        if args.sort:
            file_ = log_file(input_filepath, output_path=output_filepath)

        elif args.m_a:
            file_ = log_file(input_filepath, output_path=output_filepath)

        elif args.sus:
            file_ = log_file(input_filepath, output_path=output_filepath)

        else:
            print("Enter Correct Arguments")
    else:
        print("Invalid Input File Path")
      
   
   
    
    




        
