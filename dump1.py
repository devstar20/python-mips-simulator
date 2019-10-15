import re, sys
from ast import literal_eval 

class Simulator:
    def __init__(self, mem=1000, pc=0):
        self.data = [0 for x in range(mem)]
        self.pc = pc
        self.instructions = []
        self.labels = {}
        self.registers = { '$0' : 0, '$8': 0, '$9': 0, '$10': 0,
                           '$11': 0, '$12': 0, '$13': 0, '$14': 0,
                           '$15': 0, '$16': 0, '$17': 0, '$18': 0,
                           '$19': 0, '$20': 0, '$21': 0, '$22': 0,
                           '$23': 0, '$lo': 0, '$hi': 0}

        self.DIC = 1

    def strip_comments(self, lines):
        """Strips out comments from a list of lines."""
        ret = []
        for line in lines:
            if '#' in line: line = line[:line.find('#')]
            line = line.strip().strip('\n')
            if len(line) < 2: continue
            ret.append(line)
        return ret

    def find_labels(self, lines):
        """Records all labels in program."""
        for i, line in enumerate(lines):
            if re.compile('^.*:').match(line):
                self.labels[line.strip().rstrip(':')] = i

    def run_lines(self, lines):
        """External method to run multiple lines."""
        lines = self.strip_comments(lines)
        self.instructions.extend(lines)
        self.find_labels(lines)
        while self.pc < len(self.instructions):
            self.execute(self.instructions[self.pc])
            self.pc += 1

    def execute(self, line):
        if re.compile('^.*:').match(line): return
        if re.compile('^\.').match(line): return
        if re.compile('^(ori|or)\s+\$.{1,2},\s\$.{1,2},.*').match(line): self.move(line)
        elif re.compile('^addi\s+\$.{1,2},\s\$.{1,2},.*').match(line): self.add(line)
        elif re.compile('^(lb|sb)\s+.*').match(line): self.load_store(line)
        elif re.compile('^(slt|slti)\s+\$.{1,2},\s\$.{1,2},.*').match(line): self.set_less_than(line)
        elif re.compile('^(beq|bne)\s+\$.{1,2},\s\$.{1,2},.*').match(line): self.branch(line)
        elif re.compile('^[a-zA-Z]{2,5}\s+\$.{1,2}.*').match(line): self.logical_arithmetic(line)
        else:
            print ("Unknown command")
            raise Exception()
        self.DIC += 1


    def move(self, line):
        reg = [f.strip(' ,') for f in re.compile('\$.{1,2}').findall(line)]
        if len(reg) == 3 and line[:2] == 'or':
            r1, r2, r3 = reg[0], reg[1], reg[2] 
            self.registers[r1] = self.registers[r2] | self.registers[r3]
        elif len(reg) == 2 and line[:3] == 'ori':
            r1, r2 = reg[0], reg[1]
            n = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            self.registers[r1] = self.registers[r2] | n

    def add(self, line):
        reg = [f.strip(' ,') for f in re.compile('\$.{1,2}').findall(line)]
        if len(reg) == 2 and line[:4] == 'addi':
            r1, r2 = reg[0], reg[1]
            n = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            self.registers[r1] = self.registers[r1] + n

    def load_store(self, line):
        part = line.lstrip('sw ').lstrip('lw ')
        reg = re.compile('(\$.{1,2})').findall(line)[0].strip(' ,')
        part = part.lstrip(reg + ', ')
        try: offset = int(re.compile('\d+\(').findall(line)[0].rstrip('('))
        except: offset = 0
        addr = re.compile('\(\$.{1,2}\)').findall(line)[0].strip('(').strip(')')
        addr = self.registers[addr] + offset - literal_eval('0x2000')
        if line[:2] == 'sb':
            self.data[addr] = self.registers[reg]
        if line[:2] == 'lb':
            self.registers[reg] = self.data[addr]

    def set_less_than(self, line):
        reg = [f.strip(' ,') for f in re.compile('\$.{1,2}').findall(line)]
        if len(reg) == 3 and line[:3] == 'slt':
            r1, r2, r3 = reg[0], reg[1], reg[2]
            if self.registers[r2] < self.registers[r3]:
                self.registers[r1] = 1
            else:
                self.registers[r1] = 0
        elif len(reg) == 2 and line[:4] == 'slti':
            r1, r2 = reg[0], reg[1]
            imm = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            if self.registers[r2] < imm:
                self.registers[r1] = 1
            else:
                self.registers[r1] = 0

    def branch(self, line):
        """Handles beq and bne instructions."""
        reg = [r.strip(', ') for r in re.compile('\$.{1,2}').findall(line)]
        r1, r2 = reg[0], reg[1]

        label = line.split(' ')[-1].strip()
        #print(self.registers[r1], self.registers[r2], label, self.labels[label])
        if line[:3] == 'beq' and self.registers[r1] == self.registers[r2]:
            try:
                self.pc = self.labels[label]
            except Exception as e:
                print ("Unknown label")
                raise e
        elif line[:3] == 'bne' and self.registers[r1] != self.registers[r2]:
            try:
                self.pc = self.labels[label]
            except Exception as e:
                print ("Unknown label")
                raise e

    def logical_arithmetic(self, line):
        instr = re.compile('^[a-zA-Z]{2,5}\s').findall(line)[0].strip()
        print(instr)
        reg = [f.strip(' ,') for f in re.compile('\$.{1,2}').findall(line)]
        
        if instr == 'and' and len(reg) == 3:
            r1, r2 = reg[0], reg[1]
            r3 = reg[2]
            self.registers[r1] = self.registers[r2] & self.registers[r3]
        elif instr == "sll" and len(reg) == 2:
            r1, r2 = reg[0], reg[1]
            imm = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            self.registers[r1] = self.registers[r1] << imm
        elif instr == "lui" and len(reg) == 1:
            r1 = reg[0]
            imm = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            self.registers[r1] = imm << 16
        elif instr == "multu" and len(reg) == 2:
            r1, r2 = reg[0], reg[1]
            result = self.registers[r1] * self.registers[r2]
            self.registers['$hi'] = (result & 0xFFFFFFFF00000000) >> 32
            self.registers['$lo'] = result & 0x00000000FFFFFFFF
        elif instr == "mfhi" and len(reg) == 1:
            r1 = reg[0]
            self.registers[r1] = self.registers['$hi']
        elif instr == "mflo" and len(reg) == 1:
            r1 = reg[0]
            self.registers[r1] = self.registers['$lo']
        elif instr == 'xor' and len(reg) == 3:
            r1, r2, r3 = reg[0], reg[1], reg[2]
            self.registers[r1] = self.registers[r2] ^ self.registers[r3]
        elif instr == 'srl' and len(reg) == 2:
            r1, r2 = reg[0], reg[1]
            imm = literal_eval(re.compile('0x[\dA-F]+').findall(line)[0])
            self.registers[r1] = self.registers[r2] >> imm 
        elif instr == 'fold' and len(reg) == 1:
            r1 = reg[0]
            self.registers[r1] = (self.registers[r1] & 0xFFFF ) ^ (self.registers[r1] >> 16)
            self.registers[r1] = (self.registers[r1] & 0xFF) ^ (self.registers[r1] >> 8)
        else:
            print ("Unknown command", instr)
            raise Exception() 


def main():
    s = Simulator()
    s.run_lines( open("hash2.asm", 'r').readlines() )
    
    print("Registers-----------------")
    for key, value in s.registers.items():
        print('{0:4} : {1:8}'.format(key, format(value, '08x')))
    print("-------------------------\n")
    print("----------0x2000 - 0x2050-----------")
    for i in range(literal_eval('0x2000'), literal_eval('0x2050') + 1):
        print('{0:4} : {1:2}'.format(format(i, '04x'), format(s.data[i - literal_eval('0x2000')] ,'02x')))
    print("------------------------------------")
    print(s.DIC)
    # print(s.labels)

if __name__ == '__main__':
    main()
