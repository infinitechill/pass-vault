#! /usr/local/bin/python3
# infinite chill / 2017

import sys, os, shutil, subprocess
import random, string
import csv
import uuid,hashlib,getpass
import zipfile

passwords=[]
# todo: encrypt this file somehow...
database="._passvault/data/mystuff.csv"
updated=False

# a python class for a password object
class myPasswords(object):
    # constructor  
    def __init__(self,service,username,my_password):
        self.service = service
        self.username = username
        self.my_password = my_password
    #a function to print out the values    
    def get_pass(self):
        result=self.service+","+self.username+","+self.my_password
        return result
    def show_pass(self):
        print("")
        index = 1
        print("%-45s %-45s %-60s" % ("site","username","password"))
        print("%-45s %-45s %-60s" % (self.service,self.username,self.my_password))

# hash a password        
def hash_password(password):
    salt = uuid.uuid4().hex
    hashed_password=hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
    return hashed_password

# check that a password matches the hardcoded hashed pass
def check_password(user_password):
    #must pre hash pass word and enter here
    passlock=""
    password, salt = passlock.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

def copy_file(src, dest):
    try:
        shutil.copy(src, dest)
    except shutil.Error as e:
        print('Error: %s' % e)
    except IOError as e:
        print('Error: %s' % e.strerror)

def load_passwords(my_database):
    print("\nloading password file . . .\n")
    loaded_passwords=[]
    with open(my_database, 'r') as f:
        reader = csv.reader(f, skipinitialspace=True, delimiter='»')
        input_passwords=list(reader)
    for currpass in input_passwords:
        myPassword=myPasswords(currpass[1],currpass[3],currpass[5])
        loaded_passwords.append(myPassword)
    return loaded_passwords

# view the passwords
def view_passwords():
    print("")
    index = 1
    print("%-5s %-45s %-45s %-60s" % ("","site","user","pass"))
    for currpass in passwords:
        print("%-5d %-45s %-45s %-60s" % (index,currpass.service,currpass.username,currpass.my_password))
        index+=1
    print("")
    return

# generate a random password
def generate_pass():
    result = ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') for i in range(25))
    return result 

# generate and add a new password to database
def new_password():
    print("\nnew password : \n")
    service=input("service : ").replace(',', '')
    username=input("username : ").replace(',', '')
    my_password=generate_pass()
    myPassword=myPasswords(service,username,my_password)
    myPassword.show_pass
    verify=input("a new entry will be added for %-45s %-45s %-60s \nAre you sure? (y)es (n)o : " % (service,username,my_password))
    if (verify == "y"):
        passwords.append(myPassword)
        save_passwords()
    print("copied %s to the clipboard" % my_password)
    os.system("echo '%s' | pbcopy" % my_password)
    return

# delete a password
def delete_password():
    print("\ndelete password : \n")
    view_passwords()
    password_index=(int(input("delete password : \n")))
    while password_index <= 0 or password_index > len(passwords) :
        password_index=(int(input("delete password : \n")))
    password_index=(password_index-1)
    verify=input("are you sure? (y)es (n)o : \n")
    if (verify == "y"):
        del passwords[password_index]
        save_passwords()
    return

# edit a password
def edit_password():
    view_passwords()
    password_index=(int(input("\nedit password : \n")))
    while password_index not in range(1,len(passwords)+1):
        password_index=(int(input("\ninvalid entry. edit password : \n")))
    password_index=(password_index-1)
    passwords[password_index].show_pass()
    edit_what=(input("\n(s)ite, (u)ser, (p)ass, (c)ancel : \n"))
    while(edit_what != 's' and edit_what != 'u' and edit_what != 'p' and edit_what != 'c'):
        edit_what=(input("\n(s)ite, (u)ser, (p)ass, (c)ancel : \n"))
    if edit_what == 's':
        my_site=input("\nenter a site name : \n")
        verify=input("\nnew site name will be \" %s \" are you sure? (y)es (n)o : \n" % my_site)
        if (verify == "y"):
            passwords[password_index].service=my_site
            save_passwords()
    elif edit_what == 'u':
        my_username=input("\nenter a user name : \n")
        verify=input("\nnew user name will be \" %s \" are you sure? (y)es (n)o : \n" % my_username)
        if (verify == "y"):
            passwords[password_index].username=my_username
            save_passwords()
    elif edit_what == 'p':
        randomize=input("\n(r)andomize or (c)ustomize : \n")
        while (randomize != 'r' and randomize != 'c'):
            randomize=input("\n(r)andomize or (c)ustomize : \n")
        if randomize == 'c':
            my_password=input("\nenter a new password ( please use something secure ) : \n")
            verify=input("\nnew password will be \" %s \" are you sure? (y)es (n)o : \n" % my_password)
            if (verify == "y"):
                passwords[password_index].my_password=my_password
                save_passwords()
        elif randomize == 'r':
            my_password=generate_pass()
            verify=input("\nnew password will be \" %s \" are you sure? (y)es (n)o : \n" % my_password)
            if (verify == "y"):
                passwords[password_index].my_password=my_password
                save_passwords()
    elif edit_what == 'c':
        pass
    return

# save passwords to the file
def save_passwords():
    global updated
    password=getpass.getpass() 
    if check_password(password):
        auto_backup()
        filepath=database
        thefile = open(filepath, 'w')
        for currpass in passwords:
            thefile.write("site»%s»user»%s»pass»%s\n" % (currpass.service,currpass.username,currpass.my_password))
        updated=True
    else:
        print("\nverification failed. database not updated.\n")
    return

# copy a password to the clipboard
def get_password():
    view_passwords()
    password_index=(int(input("\ncopy password : \n")))
    while password_index <= 0 or password_index > len(passwords) :
        password_index=(int(input("\ncopy password : \n")))
    password_index=(password_index-1)
    the_password=passwords[password_index].my_password
    password=getpass.getpass() 
    if check_password(password):
        print("\ncopied %s to the clipboard\n" % the_password)
        os.system("echo '%s' | pbcopy" % the_password)
    else:
        print("\nverification failed. password not copied.\n")        


def import_passwords():
    password_file=input("\nenter a csv filepath that is in format \ne.g. site»asite.com»user»a_user»pass»a_passWord : \n")  
    password_file=os.path.join(password_file)   
    if os.path.exists(password_file):
        print("\nvalid file\n")
        try:
            input_passwords=load_passwords(password_file)
            return input_passwords
        except:
            print("\nerror importing file.\n")
            return None
    else:
        print("\nfile does not exist\n")
        return None


def backup_passwords():
    file_name=input("\nfilename: ")
    file_name=os.path.join(os.environ["HOME"],"Desktop",file_name+".csv")
    source_file=database
    confirmation= input("\nare you sure you would like to back up to %s ? (y)es, (n)o : \n" % file_name)
    if (confirmation == 'y'):
        password=getpass.getpass() 
        if check_password(password):
            copy_file(source_file, file_name)
            print("\nthe password database was backed up to",file_name)
        else: 
            print("\nverification failed.\n")
    return

# create a copy to data folder in case something happens
def auto_backup():
    file_name = get_new_file_name()
    source_file=database
    copy_file(source_file, file_name)

# returns a new filename
def get_new_file_name():
    i = 1
    while os.path.exists("._passvault/backups/%s.csv" % i):
        i += 1
    new_file= ("._passvault/backups/%s.csv" % i)
    return new_file

def un_pack():
    password=getpass.getpass()
    count=0;
    while( not check_password(password) and count < 2 ):
        password=getpass.getpass()
        count+=1
    if check_password(password):
        os.system('7z x ._passvault.zip -y -p Enter-Password-Here >/dev/null 2>&1')
    else:
        print("\nverification failed. goodbye.\n")
        sys.exit()
    return

def pack_up():
    password=getpass.getpass()
    count=0;
    while( not check_password( password ) and count < 3 ):
        password=getpass.getpass()
        count+=1
    if check_password(password):
        database=os.listdir("._passvault")
        os.system('7z -r a -p Enter-Password-Here -y -bsp0 -bso0 -bse0 ._passvault.zip ._passvault >/dev/null 2>&1')
    else:
        print("\nverification failed.\n")
        print("\nany recent changes may not have been saved. \n")
    return

def clean_up(cleanup_dir="._passvault"):
    shutil.rmtree(cleanup_dir)  
    return

# main driver function
def main():
    global passwords
    global database
    global updated
    # print greeting
    print ("\npassword manager 1.0")
    user_password = getpass.getpass()
    # password block
    if check_password(user_password) :
        un_pack()
        passwords=load_passwords(database)
        # backup the files on before allowing any modifications
        while (1):
            print("\n(v)iew, (n)ew, (d)elete, (e)dit, (b)ackup, (s)ave, (g)et, (i)mport, (q)uit\n")
            todo=input("\nwhat would you like to do : \n")
            if todo == 'v':
                view_passwords()
            elif todo == 'n':
                new_password()
            elif todo in 'd':
                delete_password()
            elif todo in 'e':
                edit_password()
            elif todo in 'b':
                backup_passwords()
            elif todo in 's':
                save_passwords()
            elif todo in 'g':
                get_password()
            elif todo in 'i':
                passwords+=import_passwords()
                save_passwords()
            if (todo=="q"):
                break;
            else:
                pass
        if updated:
            pack_up()
        if os.path.exists('._passvault.zip'):
            clean_up()
            pass
        print("\ngoodbye.\n")
    else:
        print("\nverification failed. goodbye.\n")
        sys.exit(0)




if __name__ == '__main__':

    main()