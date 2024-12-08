# Assignment_VRV_Security

> Requirement 1 (IP Address access count display in Sorted order):
- Used the data structure trie for efficient storage of the IP address.
   for example: "123.123.121.12" , "123.123.121.11", have "123.123.121" have common address, so by using this data structure common part is stored ones.
-  used the heap for the sorting the IP address. 

> Requirement 2 ( Most access end point ):
- Used hashmap to find frequency of the accessed URL
Then used the multiprocessing for efficient finding the maximum value of the most access end point.

> Requirement 3 ( Detect Suspicious Activity ):
- Suspicious activity consider IP addresses requests
   - whose login failed  greater than certain threshold 
   - whose successful access login end point requests greater than certain threshold 
   - whose login success IP address after failed  greater than certain threshold
   - whose accessed to endpoints those didn't login.
- Used hashmap to find Suspicious activity IP addresses count efficiently.

> Requirement 4:
 - Used python fs, csv module to write result to the log_analysis.csv file.

Commands  for  execution:
Requirement 1 - python parser -sort  --InputFilepath -o --OutputFilepathDirectory
Requirement 2 - python parser -m_a --InputFilepath -o --OutputFilepathDirectory
Requirement 3 - python parser -sus --InputFilepath -o --OutputFilepathDirectory
