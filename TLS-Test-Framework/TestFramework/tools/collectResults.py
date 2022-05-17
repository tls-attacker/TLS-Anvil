import pandas as pd
import os

def main(path):
    pass




read_file = pd.read_csv (r'Path where the CSV file is stored\File name.csv')
read_file.to_excel (r'Path to store the Excel file\File name.xlsx', index = None, header=True)





if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Syntax error. Missing directory path.", file=sys.stderr)
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