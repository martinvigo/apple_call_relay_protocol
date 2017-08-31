import re


regex = '<field name="data" value="([0-9a-z])+'
signature = '<field name="data" value="'

path = "/d"
outpath = "/out"


fout = open(outpath,'w')
f = open(path,'r')

while True:
    text = f.readline()
    if signature in text:
        fout.write(text[46:len(text)-3])
        fout.write("\n")

print "fin"