import re


def fn(kline):

    if "//" in kline:
        line = kline.split("//")[0].strip()
        to = kline.split("//")[1].strip()
    else:
        line = kline[:]
        to = None

    sl = line.strip().split(" ")

    normname = sl[-1][:-1]
    normtyp  = [l for l in sl[0:-1] if l != ""]

    if "[" in normname:
        arr = normname.split("[")
        normtyp.append("[")
        normtyp.append("["+arr[1])
        normname = arr[0]
    return (normname, normtyp, to)

var_names = {}
new_definitions = {}
externs = {}
var_siz = {}
siz_var = {}
var_to_type = {}

def gen_var_names_and_defs(defs, outfile, outs):

    def oprint(st):
        outfile.write(st+"\n")

    for single_def in defs:
        myaus =  [fn(i) for i in single_def[1:]]
        for fname, ftype, to in myaus:
            var_to_type[fname] = ftype

            if to is not None:
                var_siz[to] = fname
                siz_var[fname] = to

            if fname in var_names:
                continue

            base = "{}".format(fname.upper())
            def_fi = "static int "
            ext_fi = "extern int "
            if "int" in ftype or "enum" in ftype:
                cvar = base + "_FIELD_SIZE"
                new_definitions[fname]= def_fi + cvar + "= 12"
                externs[fname] = ext_fi + cvar;
                var_names[fname] = "{}".format(cvar)
            if "short" in ftype:
                cvar = base + "_FIELD_SIZE"
                new_definitions[fname]= def_fi + cvar + "= 4"
                var_names[fname] = "{}".format(cvar)
                externs[fname] = ext_fi + cvar;
            if "long" in ftype:
                cvar = base + "_FIELD_SIZE"
                new_definitions[fname]= def_fi + cvar + "= 16"
                var_names[fname] = "{}".format(cvar)
                externs[fname] = ext_fi + cvar;
            if "[" in ftype:
                cvar = base + "_SIZE_FIELD_SIZE"
                new_definitions[fname]= def_fi + cvar + "= 4"
                var_names[fname] = "{}".format(cvar)
                externs[fname] = ext_fi + cvar;
            if "struct" in ftype or "union" in ftype:
                cvar = base + "_SIZE_FIELD_SIZE"
                new_definitions[fname]= def_fi + cvar + "= 4"
                var_names[fname] = "{}".format(cvar)
                externs[fname] = ext_fi + cvar;

    for d in new_definitions:
        oprint(new_definitions[d] + ";")

    for ff in outs:
        for d in externs:
            ff.write(externs[d] + ";\n")
        ff.write("\n")

    oprint("\n")


def gen_parser(single_def, header_file, source_file):

    def hprint(st):
        header_file.write(st + "\n")

    def sprint(st):
        source_file.write(st + "\n")

    myaus =  [fn(i) for i in single_def[1:]]
    class_name = single_def[0][:-1]
    getm = lambda x: x.lower().split(" ")[1]

    hprint("int parse_{}({}* inp, char *beg);".format(getm(class_name), class_name))
    sprint("int parse_{}({}* inp, char *beg)".format(getm(class_name), class_name) + "{")

    size_so_far = []
    for fname, ftype, to in myaus:
        if to is not None:
            continue

        if "enum" in ftype:
            temp_var_name = "temp_var_{}".format(fname.lower())
            prev_size = "" if len(size_so_far) == 0 else "+" + "+".join(size_so_far)
            cur_size  = var_names[fname]
            sprint( "\t{} {} = get_{}(beg{}, {});".format("int", temp_var_name, "int", prev_size, cur_size))
            sprint( "\tinp->{} = ({}){};".format(fname, " ".join(ftype), temp_var_name))
            size_so_far.append(cur_size);
            continue

        if "int" in ftype or "long" in ftype or "short" in ftype:
            temp_var_name = "temp_var_{}".format(fname.lower())
            var_type = ftype[-1]
            prev_size = "" if len(size_so_far) == 0 else "+" + "+".join(size_so_far)
            cur_size  = var_names[fname]
            sprint( "\t{} {} = get_{}(beg{}, {});".format(" ".join(ftype), temp_var_name, var_type, prev_size, cur_size))
            sprint( "\tinp->{} = {};".format(fname, temp_var_name))
            size_so_far.append(cur_size);
            continue

        if "[" in ftype:
            temp_var_name = "read_var_{}".format(fname.lower())
            var_type = ftype[-1]
            prev_size = "" if len(size_so_far) == 0 else "+" + "+".join(size_so_far)
            cur_size  = var_names[fname]
            size_so_far.append(cur_size);

            sprint( "\tint {} = get_int(beg{}, {});".format(temp_var_name, prev_size, cur_size))

            prev_size = "" if len(size_so_far) == 0 else "+" + "+".join(size_so_far)
            krya_name = "krya_{}".format(fname.lower());
            sprint( "\t{}* {} = inp->{};".format(" ".join([i for i in ftype if "[" not in i]), krya_name, fname))

            if ("struct" in ftype or "union" in ftype) and len(ftype) > 1:
                temp_var_name_cat = "temp_{}".format(fname.lower())
                sprint( "\tint {} = 0;".format(temp_var_name_cat))
                sprint( "\tfor(int i=0; i<{}; i++)".format(temp_var_name) + "{")
                sprint( "\t\t{} = {} + parse_{}(&{}[{}], beg{});".format(temp_var_name_cat, temp_var_name_cat, ftype[1].lower(), krya_name, "i", prev_size + " + {}".format(temp_var_name_cat)))
                sprint( "\t}")
                if var_siz[fname] is not None:
                    sprint( "\tinp->{} = {};".format(var_siz[fname], temp_var_name))

                size_so_far.append(temp_var_name_cat);
            else:
                sprint( "\tget_val(&{}, beg{}, {});".format(krya_name, prev_size, temp_var_name))
                sprint( "\t{}[{}] = '\\0';".format(krya_name, temp_var_name))
                size_so_far.append(temp_var_name)
            continue

        if ("struct" in ftype or "union" in ftype) and len(ftype) > 1:
            prev_size = "" if len(size_so_far) == 0 else "+" + "+".join(size_so_far)
            new_var_name = "parsed_size_{}".format(ftype[1].lower())

            sprint( "\tint {} = parse_{}(&inp->{}, beg{});".format(new_var_name, ftype[1].lower(), fname, prev_size))
            size_so_far.append(new_var_name)
            continue
        sprint( "//ERRRRRR {} {}".format(ftype, fname))
    sprint( "\treturn {};".format("+".join(size_so_far)))
    sprint( "}")


def gen_encoder(single_def, header_file, source_file):

    myaus =  [fn(i) for i in single_def[1:]]
    class_name = single_def[0][:-1]

    def hprint(st):
        header_file.write(st + "\n")

    def sprint(st):
        source_file.write(st + "\n")

    hprint("int encode_{}({}* inp, char** st);".format(getm(class_name), class_name))
    sprint("int encode_{}({}* inp, char** st)".format(getm(class_name), class_name) + "{")
    sprint("\tchar *saveto = *st;")

    base = ""

    formater = []
    for fname, ftype, to in myaus:
        #sprint("\t", fname, ftype)

        if to is not None:
            print "Ignoring the encoding of ", fname, ftype, to
            continue

        if "enum" in ftype:
            base += "%.*d"
            formater.append("{} < 0? {}-1 : {}".format("inp->{}".format(fname), var_names[fname], var_names[fname]))
            formater.append("inp->{}".format(fname))
        if "int" in ftype:
            base += "%.*d"
            formater.append("{} < 0? {}-1 : {}".format("inp->{}".format(fname), var_names[fname], var_names[fname]))
            formater.append("inp->{}".format(fname))
        elif "long" in ftype and "unsigned" in ftype:
            base += "%.*lu"
            formater.append("{} < 0? {}-1 : {}".format("inp->{}".format(fname), var_names[fname], var_names[fname]))
            formater.append("inp->{}".format(fname))
        elif "long" in ftype:
            base += "%.*ld"
            formater.append("{} < 0? {}-1 : {}".format("inp->{}".format(fname), var_names[fname], var_names[fname]))
            formater.append("inp->{}".format(fname))
        elif "char" in ftype and "[" in ftype:
            base += "%.*d%s"
            formater.append(var_names[fname])
            formater.append("strlen(inp->{})".format(fname))
            formater.append("inp->{}".format(fname))
        elif ("struct" in ftype or "union" in ftype) and "[" not in ftype:
            # base += "%.*d%s"
            base += "%s"

            nvar_name = "temp_{}".format(fname.lower())
            nvar_name_ptr = "{}_ptr".format(nvar_name)
            nvar_len_name = "temp_len_{}".format(fname.lower())
            sprint("\tchar {}[{}], *{}={};".format(nvar_name, "MTU", nvar_name_ptr, nvar_name))
            sprint("\tbzero({}, {});".format(nvar_name, "MTU"))

            sprint("\tint {} = encode_{}(&inp->{}, &{});".format(nvar_len_name, ftype[1].lower(), fname, nvar_name_ptr))
            # formater.append(var_names[fname])
            # formater.append(nvar_len_name)
            formater.append(nvar_name)
        elif ("struct" in ftype or "union" in ftype) and "[" in ftype:
            base += "%.*d%s"
            final_var = "final_var_{}".format(fname.lower())
            nvar_name = "temp_{}".format(fname.lower())
            nvar_len_name = "temp_len_{}".format(fname.lower())
            inner_temp_var = "innertemp"
            inner_temp_var_ptr = "{}_ptr".format(inner_temp_var)
            siz = "inp->{}".format(var_siz[fname])

            sprint("\tchar {}[{}];".format(nvar_name, "MTU"))
            sprint("\tchar {}[{}];".format(final_var, "MTU"))
            sprint("\tbzero({}, {});".format(final_var, "MTU"))
            sprint("\tfor(int i=0; i < {}; i++)".format(siz) + "{")
            sprint("\t\tbzero({}, {});".format(nvar_name, "MTU"))
            sprint("\t\tchar {}[{}], *{}={};".format(inner_temp_var, "MTU", inner_temp_var_ptr, inner_temp_var))
            sprint("\t\tbzero({}, {});".format(inner_temp_var_ptr, "MTU"))
            # sprint("\t\tint {} = encode_{}(&inp->{}[{}], &{});".format(nvar_len_name, ftype[1].lower(), fname, "i", inner_temp_var_ptr))
            # sprint("\t\tsprintf({}, \"%.*d%s\", {}, {}, {});".format(nvar_name, var_names[fname], nvar_len_name, inner_temp_var_ptr))
            sprint("\t\tint {} = encode_{}(&inp->{}[{}], &{});".format(nvar_len_name, ftype[1].lower(), fname, "i", inner_temp_var_ptr))
            sprint("\t\tsprintf({}, \"%s\", {});".format(nvar_name, inner_temp_var_ptr))
            sprint("\t\tstrcat({}, {});".format(final_var, nvar_name))
            sprint("\t}")

            formater.append(var_names[fname])
            formater.append(siz)
            formater.append(final_var)

    sprint("\tconst char* format=\"{}\";".format(base))
    sprint("\treturn sprintf(saveto, format, {});".format(", ".join(formater)))

    sprint("}")
    sprint("\n")

def gen_tests(defs, header_file, source_file):
    def hprint(st):
        header_file.write(st + "\n")

    def sprint(st):
        source_file.write(st + "\n")

    base = """
#include <stdio.h>
#include <assert.h>
#include <strings.h>

#include <string.h>
#include <time.h>

#include "../headers/caml_common.h"
#include "../headers/protocol_common.h"
#include "../headers/protocol.h"
#include "../headers/protocol_parser.h"
#include "../headers/protocol_encoder.h"
#include "../headers/protocol_protocol_test.h"
#include "../headers/utils.h"

unsigned short PRIO_LOG = PRIO_HIGH;
extern int MTU;

void gen_random_string(char *s, const int len) {
static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

for (int i = 0; i < len; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
}

s[len] = 0;
}

long lrand() {
    return 10l;
}

"""
    sprint(base)
    methods_to_invoke = []

    for single_def in defs:
        myaus =  [fn(i) for i in single_def[1:]]
        class_name = single_def[0][:-1]

        hprint("void populate_{}({}* inmsg);".format(getm(class_name), class_name))
        sprint("void populate_{}({}* inmsg)".format(getm(class_name), class_name) + "{")
        # sprint("\t{}* r = ({}*) malloc(sizeof({}));".format(class_name, class_name, class_name)

        tch, tnum, tl, tstruct, kryastruct = [], [], [], [], []
        for fname, ftype, to in myaus:
            if "int" in ftype:
                if to is None:
                    sprint ("\tinmsg->{} = rand();".format(fname))
                else:
                    maxsize = var_to_type[to][-1][1:-1]
                    print var_to_type[to]
                    sprint ("\tinmsg->{} = 1 + arc4random_uniform({}-1);".format(fname, maxsize))
                tnum.append(fname)
            elif "long" in ftype:
                sprint ("\tinmsg->{} = lrand();".format(fname))
                tl.append(fname)
            elif "char" in ftype and "[" in ftype:
                sprint ("\tgen_random_string(inmsg->{}, 10);".format(fname))
                tch.append(fname)
            elif ("struct" in ftype or "union" in ftype) and "[" not in ftype:
                sprint ("\tpopulate_{}(&inmsg->{});".format(getm(" ".join(ftype)), fname))
                tstruct.append((fname, ftype))
            elif ("struct" in ftype or "union" in ftype) and "[" in ftype:
                sprint ("\tfor(int i=0; i < inmsg->{}; i++)".format(var_siz[fname]) + "{")
                sprint ("\t\tpopulate_{}(&inmsg->{}[{}]);".format(getm(" ".join(ftype)), fname, "i"))
                sprint ("\t}")

                kryastruct.append((fname, ftype))

        sprint("}")

        hprint("int test_{}({}* inmsg, {}* outmsg);".format(getm(class_name), class_name, class_name))
        sprint("int test_{}({}* inmsg, {}* outmsg)".format(getm(class_name), class_name, class_name) + "{")

        sprint("\tprintf(\"Testing {} ...\\n\");".format(getm(class_name)))
        methods_to_invoke.append(("test_{}({}, {});".format("".join(getm(class_name).split(" ")),  "inmsg_{}".format("".join(getm(class_name).split(" "))), "outmsg_{}".format("".join(getm(class_name).split(" ")))), class_name))

        sprint("\tchar* out = (char*) malloc(sizeof(char) * MTU);")

        sprint("\tint t = encode_{}(inmsg, &out);".format(getm(class_name)))
        sprint("\tprintf(\"ENCODED: '%s'[%d]\\n\", out, t);")

        sprint("\tparse_{}(outmsg, out);".format(getm(class_name)))

        for i in tch:
            sprint("\tprintf(\"{} %s ?= %s = %d\\n\", inmsg->{}, outmsg->{}, strcmp(inmsg->{}, outmsg->{})==0);".format(i, i, i, i, i))
            sprint("\tassert(strcmp(inmsg->{}, outmsg->{}) == 0);".format(i, i))

        for i in tl:
            sprint("\tprintf(\"{} %ld ?= %ld = %d\\n\", inmsg->{}, outmsg->{}, inmsg->{}==outmsg->{});".format(i, i, i, i, i))
            sprint("\tassert(inmsg->{} == outmsg->{});".format(i, i))

        for i in tnum:
            sprint("\tprintf(\"{} %d ?= %d = %d\\n\", inmsg->{}, outmsg->{}, inmsg->{}==outmsg->{});".format(i, i, i, i, i))
            sprint("\tassert(inmsg->{} == outmsg->{});".format(i, i))

        for ffn, fft in tstruct:
            if "union" not in fft:
                sprint("\ttest_{}(&inmsg->{}, &outmsg->{});".format(getm(" ".join(fft)), ffn, ffn))

        for ffn, fft in kryastruct:
            sprint ("\tfor(int i=0; i < inmsg->{}; i++)".format(var_siz[ffn]) + "{")
            sprint ("\t\ttest_{}(&inmsg->{}[{}], &outmsg->{}[{}]);".format(getm(" ".join(fft)), ffn, "i", ffn, "i"))
            sprint ("\t}")

        sprint("\tfree(out);")
        sprint("\tprintf(\"=======================\\n\");")
        sprint("\treturn 0;")
        sprint("}")

    sprint("\nint main(){")
    for i, cn in methods_to_invoke:
        if "union" not in cn:
            sprint("\t{}* inmsg_{} = ({}*) malloc(sizeof({}));".format(cn, "".join(getm(cn).split(" ")), cn, cn))
            sprint("\t{}* outmsg_{} = ({}*) malloc(sizeof({}));".format(cn, "".join(getm(cn).split(" ")), cn, cn))
            sprint ("\tpopulate_{}(inmsg_{});".format(getm(cn), "".join(getm(cn).split(" ")), fname))
            sprint("\t" + i)

            sprint("\tfree(inmsg_{}); free(outmsg_{});".format("".join(getm(cn).split(" ")), "".join(getm(cn).split(" "))))

    sprint("\treturn 0;\n}")

defs_file = open("./headers/protocol.h", "r")

getm = lambda x: x.lower().split(" ")[1]
defs = []

lines = defs_file.readlines()

definition_pattern = re.compile("((struct)|(union)) [A-Za-z]+{")

i = 0
while(i < len(lines)):
    line = lines[i]

    if definition_pattern.match(line.strip()) is not None:
        new_def = []
        for j in xrange(i, len(lines)):
            nline = lines[j]

            if nline.strip().endswith("};"):
                defs.append(new_def)
                i = j
                break
            if nline.strip() != "":
                new_def.append(nline.strip())

    i+=1


def wheaders(mfile):
    mfile.write("#include \"../headers/message.h\""+"\n")
    mfile.write("#include \"../headers/protocol.h\""+"\n")
    mfile.write("#include \"../headers/protocol_common.h\""+"\n")
    mfile.write("#include <strings.h>"+"\n")
    mfile.write("#include <stdio.h>"+"\n")
    mfile.write("\n")

def ifdef_header(mfile, head):
    mfile.write("#ifndef {}\n".format(head))
    mfile.write("#define {}\n".format(head))

def endif(mfile):
    mfile.write("#endif")

parser_header_filen, parser_source_filen = "headers/protocol_parser.h", "src/protocol_parser.c"
parser_header_file, parser_source_file = open(parser_header_filen, "w"), open(parser_source_filen, "w")
encoder_header_filen, encoder_source_filen = "headers/protocol_encoder.h", "src/protocol_encoder.c"
encoder_header_file, encoder_source_file = open(encoder_header_filen, "w"), open(encoder_source_filen, "w")

protocol_test_header_filen, protocol_test_source_filen = "headers/protocol_protocol_test.h", "src/protocol_protocol_test.c"
protocol_test_header_file, protocol_test_source_file = open(protocol_test_header_filen, "w"), open(protocol_test_source_filen, "w")


ifdef_header(parser_header_file, "PROTOCOL_PARSER_H")
ifdef_header(encoder_header_file, "PROTOCOL_ENCODER_H")


wheaders(encoder_header_file)
wheaders(encoder_source_file)
wheaders(parser_header_file)
wheaders(parser_source_file)

protocol_common = open("headers/protocol_common.h", "w")
ifdef_header(protocol_common, "PROTOCOL_COMMON_H")

gen_var_names_and_defs(defs, protocol_common, [
    encoder_header_file,
    encoder_source_file,
    parser_header_file,
    parser_source_file
])

for dd in defs:

    gen_parser(dd, parser_header_file, parser_source_file)

    gen_encoder(dd, encoder_header_file, encoder_source_file)

gen_tests(defs, protocol_test_header_file, protocol_test_source_file)

endif(parser_header_file)
endif(encoder_header_file)
endif(protocol_common)
