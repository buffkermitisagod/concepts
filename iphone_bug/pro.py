
def main():
    print("[-] reading from files...")
    file = open("ap.txt","r")
    f = file.readlines()
    file.close()

    file = open("mac.txt","r")
    g = file.readlines()
    file.close()

    ap = []
    mac = []

    print("[-] proccesing...")
    for b in range(len(f)):
        x = f[b]
        mc = g[b]
        if "\x00" in x or "'" in x:
            pass
        else:
            x = x.replace("-","")
            x = x.replace(" "," ")
            ap.append(x)
            mac.append(mc)

    print("[-] saving...")

    file = open("ap_new.txt","r+")
    file.writelines(ap)
    file.close()

    file = open("mac_new.txt","r+")
    file.writelines(mac)
    file.close()

if __name__ == "__main__":
    main()