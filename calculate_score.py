import argparse
import csv
import json
import urllib.parse


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", dest = "input", help="Argument \"i\" takes the path to the json output from FastDAST that you want to caclucate an OWASP score for.", type=str, required = True)
parser.add_argument("-c", "--class", dest = "class_name", help="Argument \"c\" takes a string that represents the FastDAST checker you want to calculate a score for.", type=str, required = True)

args = parser.parse_args()

fd_class_map = {
    "XSS": "Cross Site Scripting",
    "SQLI": "SQL Injection",
    "CMD": "Command Injection",
    "COOKIES": "Unsecured Session Cookie",
    "PATHTRAV": "Path Traversal", 
}

owasp_class_map = {
    "XSS": "XSS",
    "SQLI": "SQL",
    "CMD": "OSCmding",
    "COOKIES": "UnsecCk",
    "PATHTRAV": "PathTrav"
    }


def build_answer_key():
    answer_key = {}
    with open("owasp-benchmark-answer-key.csv", "r") as f:
        reader = csv.reader(f)
        # turn the first row into the columns for the dictionaries cuz I don't want to write them myself.
        columns = f.readline().replace('\n','').replace('\r','').replace('\ufeff','').split(',')
        # Process each row of the csv file.
        for row in reader:
            answer = {}
            for i in range(len(columns)):
                answer[columns[i]] = row[i]
                key = urllib.parse.urlparse(row[2]).path
                answer_key[key] = answer
    return answer_key

def get_vulns(input_file, class_name):
    with open(input_file, "r") as f:
        data = json.load(f)
        vulns = []
        for vuln in data["vulnerabilities"]:
            if class_name in vuln["attackClass"]["name"]:
                vulns.append(vuln)
    return vulns

def get_counts(vulns, answer_key):
    tp_count = 0
    fp_count = 0
    total = 0
    # Get tp and fp counts
    for vuln in vulns:
        key = vuln["exchange"]["request"]["url"]["Path"]
        if answer_key[key]:
            # print(answer_key[key])
            if answer_key[key]["real"]:
                tp_count += 1
            else:
                fp_count += 1
        else:
            print("Key not found in answer key: "+ key)
    
    # Get total count
    for key in answer_key:
        if answer_key[key]["class"] == owasp_class_map[args.class_name] and answer_key[key]["real"] == "TRUE":
            total += 1


    return tp_count, fp_count, total


answer_key = build_answer_key()
vulns = get_vulns(args.input,fd_class_map[args.class_name])
print("Found " + str(len(vulns)) + " vulnerabilities of type " + args.class_name)

tp_count, fp_count, total = get_counts(vulns, answer_key)

print("True Positives: " + str(tp_count))
print("False Positives: " + str(fp_count))
print("Total: " + str(total))
score = round(100 * (tp_count - fp_count)/total, 2)
print("Score: " + str(score))