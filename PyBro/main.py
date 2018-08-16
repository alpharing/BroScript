import autoPy
import pickle
import sys

def sig2notice(list_sig):
    try:
        list_temp = []
        list_file = []

        list_before = []
        list_after = []
        list_middle = []

        list_addSig = []

        parse_Scnt = 0
        parse_Ecnt = 0

        with open('main.bro', 'r') as f:
            list_temp = f.readlines()

        show_proto(list_sig)

        # Find Parse count
        for i in range(0, len(list_temp)):
            if list_temp[i].count("End of Notice"):
                parse_Ecnt = i

        for i in range(0, len(list_temp)):
            if list_temp[i].count("Start of Notice"):
                parse_Scnt = i

        # Parsing
        for i in range(0, parse_Scnt):
            list_before.append(list_temp[i])

        for i in range(parse_Scnt, parse_Ecnt):
            list_middle.append(list_temp[i])

        for i in range(parse_Ecnt, len(list_temp)):
            list_after.append(list_temp[i])

        # Reset Notice Part
        print(list_middle)
        list_middle[1:] = []
        print(list_middle)

        # Making Notice Part
        for i in list_sig:
            list_addSig.append('\n')
            list_addSig.append('\tif ( /' + i.name + '/ in state$sig_id ) {\n')
            list_addSig.append('\t\tprint("' + i.name + ' founded");\n')
            list_addSig.append('\t\tNOTICE([$note=ProtoSig::Malware, $msg="' + i.name + ' founded",\n')
            list_addSig.append('            \t\t$conn=state$conn, \n')
            list_addSig.append('            \t\t$identifier=fmt("%s%s", '
                               'state$conn$id$orig_h, state$conn$id$resp_h)]);\n')
            list_addSig.append('\t}\n')

        list_before.extend(list_middle)
        list_before.extend(list_addSig)
        list_before.extend(list_after)

        with open('main.bro', 'w') as f:
            f.writelines(list_before)

    except BaseException as e:
        print(e)

# .sig file maker
def make_file(list_sig):
    try:

        # Create file
        with open('protosigs.sig', 'w') as f:
            for sig in list_sig:
                print("signature protosig_" + sig.name + " {", file=f)
                print("\tip-proto == " + sig.ip_proto, file=f)
                for i in sig.payload:
                    print("\tpayload /" + i + "/", file=f)
                print("\ttcp-state " + sig.tcp_state, file=f)
                print("\t" + sig.eval, file=f)
                print("}\n", file=f)

        # Make dump file
        with open('save.sig', 'wb') as f:
            pickle.dump(list_sig, f)

    except IOError as e:
        print(e)

# Add signatre
def make_proto():
    try:

        list_sig = []

        while(1):
            code = 0

            print("1. signature create")
            print("2. exit")

            code = int(input())

            if code == 2:
                break
            elif code == 1:
                newClass = autoPy.proto_sig()
                newClass.make_sig()
                newClass.print_sig()
                list_sig.append(newClass)
            else:
                print("Please Put in 1 or 2 ")
                continue

        return list_sig


    except BaseException as e:
        print(e)

# Load your .sig File
def load_sigFile():
    try:
        # Temporary List
        list_temp = []
        list_file = []
        list_sig = []
        jump_cnt = 0

        # Loading original .sif File
        with open('protosigs.sig', 'r') as f:
            list_temp = f.readlines()

        # Featuring Data
        for i in list_temp:
            i = i.replace('\t', '')
            list_file.append(i.replace('\n', ''))

        i = 0

        while(i < len(list_file)):

            i += jump_cnt
            jump_cnt = 0

            if list_file[i].count('{') == 1:
                # Temporary Signature Class
                temp_sig = autoPy.proto_sig()

                list_temp = list_file[i].split(' ')
                temp_sig.name = list_temp[1][9:]
                jump_cnt += 1

                if list_file[i+1].count('ip-proto'):
                    list_temp = list_file[i+1].split(' ')
                    temp_sig.ip_proto = list_temp[2]
                    jump_cnt += 1

                # Suppose Max_Payload value is 3
                for j in range(i+2, len(list_file)-1):

                    if list_file[j] == '}':
                        break

                    if list_file[j].count('/') >= 2:

                        if list_file[j] == '}':
                            break

                        list_temp = list_file[j].split('payload')
                        temp_sig.payload.append(list_temp[1])
                        jump_cnt += 1

                if list_file[i+jump_cnt].count('tcp-state') == 1:
                    list_temp = list_file[i+jump_cnt].split('tcp-state')
                    temp_sig.tcp_state = list_temp[1].lstrip()
                    jump_cnt += 4

            list_sig.append(temp_sig)
        # end Featuring Data

    except BaseException as e:
        return list_sig

# Append original signature
def append_proto(list_sig):
    try:

        # Loading original signature Dump file
        with open('save.sig', 'rb') as f:
            list_orig = pickle.load(f)

        list_orig += list_sig

        return list_orig

    except IOError as e:
        print(e)

# Find and Delete
def delete_proto(list_sig):

    show_proto(list_sig)
    index = -1

    print("\n\nname : protosig_<this part>")
    text = input("Enter the name of the signature you want to delete : ")

    for sig in list_sig:
        index += 1
        if sig.name == text:
            break

    list_sig.pop(index)

    print("\n\n[Your Signature After deleting]")
    show_proto(list_sig)

# Show Signature
def show_proto(list_sig):

    print("[Your Signature]")

    for sig in list_sig:
        print("signature protosig_" + sig.name)

if __name__ == '__main__':

    '''
    # test field
    a = autoPy.proto_sig('hi')
    b = autoPy.proto_sig('by')
    c = autoPy.proto_sig('u')

    null_list = []
    null_list.append(a)
    null_list.append(b)
    null_list.append(c)
    make_file(null_list)

    null_list = append_proto(null_list)
    show_proto(null_list)
    '''

    null_list = []
    null_list = load_sigFile()

    sig2notice(null_list)
