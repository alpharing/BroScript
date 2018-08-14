import autoPy
import pickle
import sys

# .sig file maker
def make_file(list_sig):
    try:

        # 파일 생성
        with open('protosig.sig', 'w') as f:
            for sig in list_sig:
                print("signature protosig_" + sig.name + " {", file=f)
                print("\tip-proto == " + sig.ip_proto, file=f)
                for i in sig.payload:
                    print("\tpayload /" + i + "/", file=f)
                print("\ttcp-state " + sig.tcp_state, file=f)
                print("\t" + sig.eval, file=f)
                print("}\n", file=f)

        # 덤프 파일 만들기
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

            print("1. signature 생성")
            print("2. 종료")

            code = int(input())

            if code == 2:
                break
            elif code == 1:
                newClass = autoPy.proto_sig()
                newClass.make_sig()
                newClass.print_sig()
                list_sig.append(newClass)
            else:
                print("1 or 2 만 입력하세요")
                continue

        return list_sig


    except BaseException as e:
        print(e)

# Append original signature
def append_proto(list_sig):
    try:

        # Loading original signature file
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

    print("\n\n이름 : protosig_<이 부분>")
    text = input("삭제하고 싶은 시그니쳐의 이름을 입력하세요 : ")

    for sig in list_sig:
        index += 1
        if sig.name == text:
            break

    list_sig.pop(index)

    print("\n\n[삭제 한 후 보유하고 있는 시그니쳐 이름]")
    show_proto(list_sig)

# Show Signature
def show_proto(list_sig):

    print("[보유하고 있는 시그니쳐 이름]")

    for sig in list_sig:
        print("signature protosig_" + sig.name)

if __name__ == '__main__':

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