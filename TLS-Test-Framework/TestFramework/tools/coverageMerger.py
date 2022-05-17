import os
import re
import sys
from subprocess import PIPE, Popen

"""
Program Description:
    Collects the coverage data from the respective directory in the docker volume that contains the coverage data for
    several builds (named "CoverageReport_<Date>") and outputs the coverage results with the merged results in a csv file.
    The output file is created in the passed directory.

Syntax is:
    python3 coverageMerger.py <coverage_report_directory_path>
e.g:
    python3 ./coverageMerger.py ./CoverageReport_2022-01-02T03-04-05Z
"""

class ReportEntry:
    def __init__(self, value: int, maxValue: int):
        self.value = value
        self.maxValue = maxValue

    def getPercentage(self):
        percentage = (float(self.value)) / float(self.maxValue)
        return f"{percentage:.4f}"


    def __str__(self):
        return f"{self.value}/{self.maxValue} ({self.getPercentage()})"

class ReportResults:
    def __init__(self, functionCoverage: ReportEntry, lineCoverage: ReportEntry):
        self.functionCov = functionCoverage
        self.lineCov = lineCoverage

class CoverageReport:
    linesRe = re.compile(r"lines......: ([0-9.]*)% \((\d*) of (\d*) lines\)", re.MULTILINE)
    functionsRe = re.compile(r"functions..: ([0-9.]*)% \((\d*) of (\d*) functions\)", re.MULTILINE)

    def __init__(self, tag, coverageFilePath):
        self.tag = tag
        self.coverageFilePath = coverageFilePath
        self.reportResults = None

    def __str__(self):
        reportRes = self.getReportResults()
        return f"[tag='{self.tag}', res: {reportRes.functionCov} functions, {reportRes.lineCov} lines]"

    def getReportResults(self):
        if self.reportResults:
            return self.reportResults

        p = Popen(f"lcov --summary {self.coverageFilePath}", shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        res = stdout.decode("utf-8")
        err = stderr.decode("utf-8")

        if(len(err) > 0):
            print(f"Error: {err}", file=sys.stderr)

        lineMatch = self.linesRe.search(res)
        functionMatch = self.functionsRe.search(res)

        self.reportResults = ReportResults(ReportEntry(int(functionMatch.group(2)), int(functionMatch.group(3))), ReportEntry(int(lineMatch.group(2)), int(lineMatch.group(3))))

        return self.reportResults

    def getCsvLine(self):
        r = self.getReportResults()
        lineCov = r.lineCov
        functionCov = r.functionCov
        line = ",".join([self.tag, 
        str(lineCov.value), str(lineCov.maxValue), lineCov.getPercentage(), 
        str(functionCov.value), str(functionCov.maxValue), functionCov.getPercentage()])
        return line

        

def getMergedCoverageReport(infoFileList: list, outPath):
    outFileName = "merged.info"
    outFilePath = os.path.join(outPath,outFileName)
    command = ["lcov"]
    for infoFile in infoFileList:
        command.append("-a")
        command.append(infoFile)
    
    command.append("-o")
    command.append(outFilePath)

    commandStr = " ".join(command)
    p = Popen(commandStr, shell=True, stdout=PIPE, stderr=PIPE)
    _, _ = p.communicate()

    res = CoverageReport("Collectively", outFilePath)
    return res

    

def main(path):
    dirTags = [o for o in os.listdir(path) if os.path.isdir(os.path.join(path,o))]
    partialReports = []

    for tag in dirTags:
        dirPath = os.path.join(path,tag)
        coverageFilePath = None
        for fname in os.listdir(dirPath):
            if fname.endswith('.info'):
                coverageFilePath = os.path.join(dirPath,fname)
                partialReports.append(CoverageReport(tag, coverageFilePath))
                # do stuff on the file
                break

        if not coverageFilePath:
            continue

    if(len(partialReports) < 1):
        print(f"Error: No coverage data in path '{path}' found.", file=sys.stderr)
        exit(1)

    # Progress info 
    for r in partialReports:
        print(f"\rProcess: {r}".ljust(120), end="")

    print(f"\rProcess: Merge Reports...".ljust(120), end="")
    mergedReport = getMergedCoverageReport([pr.coverageFilePath for pr in partialReports], path)
    print(f"\rProcess: {mergedReport}".ljust(120), end="")

    outFilePath = os.path.join(path,"coverage_overview.csv")
    with open(outFilePath, 'w') as outFile:
        header = ",".join(["Tag", "Lines Covered", "Lines Max", "Lines Coverage", "Functions Covered", "Functions Max", "Function Coverage"])

        outFile.write(f'{header}\n')#
        r: CoverageReport
        for r in partialReports:
            outFile.write(f"{r.getCsvLine()}\n")
        outFile.write(f"{mergedReport.getCsvLine()}\n")

    print(f"\rDone! Output file: '{outFilePath}'".ljust(120))

def lcovInstalled():
    p = Popen(f"lcov -v", shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    res = stdout.decode("utf-8")
    err = stderr.decode("utf-8")

    return "LCOV version" in res
    


def printHelp():
    print("Syntax is:")
    print(f"  {sys.argv[0]} <coverage_report_directory_path>")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Syntax error. Missing coverage directory path.", file=sys.stderr)
        printHelp()
        exit(1)
    
    path = sys.argv[1]
    if not os.path.isdir(path):
        print(f"Error: Directory '{path}' cannot be found.", file=sys.stderr)
        printHelp()
        exit(1)

    if not lcovInstalled():
        print("Lcov is not installed. To install lcov on ubuntu run: \n"
              "sudo apt update\n"
              "sudo apt install lcov\n"
               ,file=sys.stderr)


    main(path)