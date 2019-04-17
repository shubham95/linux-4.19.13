import os
import filecmp

# Set the directory you want to start from
orgfilepath = []
modfilepath = []
root_org_Dir = '/home/uchiha/Downloads/linux_original/linux-4.19.13'
root_mod_Dir = '/home/uchiha/Desktop/linux-4.19.13'
cnt =0
for dirName, subdirList, fileList in os.walk(root_org_Dir):
    #print('Found directory: %s' % dirName)
    #cnt = cnt +1
    for fname in fileList:
            file1 = os.path.join(dirName, fname)
            file2 = root_mod_Dir + file1[51:]
            if(filecmp.cmp(file1, file2)==False):
                print(file1+str('\n')+str(cnt))
                cnt=cnt+1
            #print(file1 ,file2 +str("\n") +str(cnt))
           
        #print('\t%s' % fname)
print(orgfilepath)
