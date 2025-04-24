# OWASP Score Calculator

## Usage
The script takes two arguments `-i/-input` and `-c/-class`.  
Input is the file path to the json results output file from a FastDAST scan you want to score.  
Class is the FastDAST short name for the class you are scoring against OWASP.  

Example 
```
python3 calculate_score.py -i ./fd_results/fastdast_owasp_xss.json -c XSS
```

Results are printed to stout.

```
Found 126 vulnerabilities of type XSS
True Positives: 126
False Positives: 0
Total: 246
Score: 51.22
```