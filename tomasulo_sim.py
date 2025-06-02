import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, font
import re
from copy import deepcopy

# ---------------- Assembly Parser ----------------
def parse_asm(code_text):
    code_text = code_text.lstrip('\ufeff')
    raw_lines = code_text.splitlines()
    lines = []
    for L in raw_lines:
        m = re.match(r'^\s*([0-9A-Fa-f]+):\s*(.*)$', L)
        lines.append(m.group(2) if m else L)
    labels, addr = {}, 0
    for L in lines:
        s = L.split('#', 1)[0].strip()
        if not s or s.startswith('#') or s.startswith('.'):
            continue
        if re.match(r'^[A-Za-z_]\w*:$', s):
            labels[s[:-1]] = addr
        else:
            addr += 4
    instrs, addr = [], 0
    for lbl, a in labels.items():
        instrs.append({'addr': a, 'op': 'label', 'args': [], 'raw': lbl + ':'})
    for L in lines:
        s = L.split('#', 1)[0].strip()
        if not s or s.startswith('#') or s.startswith('.') or re.match(r'^[A-Za-z_]\w*:$', s):
            continue
        parts = [p for p in re.split(r'[ ,\s()]+', s) if p]
        instrs.append({'addr': addr, 'op': parts[0].lower(), 'args': parts[1:], 'raw': s})
        addr += 4
    instrs.sort(key=lambda ins: ins['addr'])
    return instrs

# ---------------- Tomasulo CPU ----------------
class TomasuloCPU:
    def __init__(self, instr_list, latencies):
        self.LAT = latencies
        self.stats = {
            'cycles': 0,
            'raw_stalls': 0,
            'war_eliminated': 0,
            'load_count': 0,
            'store_count': 0,
            'load_cycles': 0,
            'add_cycles': 0,
            'mult_cycles': 0
        }
        self.instr_list = instr_list[:]
        self.instrs = {i['addr']: deepcopy(i) for i in instr_list if i['op'] != 'label'}
        self.regs = [0] * 32
        self.rename_table = [None] * 32
        self.fregs = [0.0] * 32
        self.frename_table = [None] * 32
        self.next_tag = 1
        def make_rs(name, count):
            return [{  # reservation station entry
                'name': f'{name}{i+1}', 'busy': False, 'op': None,
                'Vj': None, 'Vk': None, 'Qj': None, 'Qk': None,
                'dst': None, 'tag': None, 'addr': None, 'ins_addr': None,
                'imm': 0, 'mem_addr': None, 'value': None,
                'remaining': 0, 'ready': False, 'exec_started': False,
                'stalled_flag': False,  # for RAW stall counting
                'src_regs': []  # track source registers pre-rename
            } for i in range(count)]
        self.load_rs = make_rs('load', 2)
        self.add_rs = make_rs('add', 2)
        self.mult_rs = make_rs('mult', 2)
        self.instr_status = {i['addr']: {'Issue': None, 'ExecStart': None, 'ExecComplete': None, 'WriteBack': None}
                             for i in instr_list if i['op'] != 'label'}
        self.pending = [i['addr'] for i in instr_list if i['op'] != 'label']
        self.memory = [0] * 4096
        self.history = []

    def step(self):
        # snapshot history
        self.history.append(deepcopy({
            'regs': self.regs, 'rename': self.rename_table,
            'fregs': self.fregs, 'frename': self.frename_table,
            'rs': (self.load_rs, self.add_rs, self.mult_rs),
            'instr_status': self.instr_status, 'pending': self.pending.copy(),
            'stats': self.stats.copy()
        }))
        self.stats['cycles'] += 1
        all_rs = self.load_rs + self.add_rs + self.mult_rs

        # Write-back stage
        for rs in all_rs:
            if rs['busy'] and rs['ready']:
                dst, producer, val = rs['dst'], rs['name'], rs['value']
                if dst is not None and producer:
                    if self.frename_table[dst] == producer:
                        self.fregs[dst] = val
                        self.frename_table[dst] = None
                    elif self.rename_table[dst] == producer:
                        self.regs[dst] = val
                        self.rename_table[dst] = None
                pc = rs['ins_addr']
                self.instr_status[pc]['WriteBack'] = self.stats['cycles']

        # Broadcast & cleanup
        for rs in all_rs:
            if rs['busy'] and rs['ready']:
                # broadcast to other RS
                producer = rs['name']
                for dest in all_rs:
                    for q, f in (('Qj','Vj'),('Qk','Vk')):
                        if dest[q] == producer:
                            dest[f] = rs['value']
                            dest[q] = None
                # reset RS fields
                for k in ['busy','op','Vj','Vk','Qj','Qk','dst','tag','addr','ins_addr','imm','value']:
                    rs[k] = None
                rs['mem_addr'] = None
                rs['remaining'] = 0
                rs['ready'] = False
                rs['exec_started'] = False
                rs['stalled_flag'] = False
                rs['src_regs'] = []

        # Execute stage
        for kind, units in (('load', self.load_rs), ('add', self.add_rs), ('mult', self.mult_rs)):
            for rs in units:
                if not rs['busy'] or rs['ready']:
                    continue
                op = rs['op']
                typ = 'load' if op in ('lw','ldc1') else ('add' if op in ('add','addi','addiu','sub','add.d','sub.d') else 'mult')
                # count load issue once
                if not rs['exec_started'] and typ == 'load':
                    self.stats['load_count'] += 1
                # check RAW stall once per instruction
                ready = (typ == 'load') or (rs['Qj'] is None and rs['Qk'] is None)
                if not rs['exec_started'] and not ready and not rs['stalled_flag']:
                    self.stats['raw_stalls'] += 1
                    rs['stalled_flag'] = True
                # start execution
                if not rs['exec_started'] and ready:
                    pc = rs['ins_addr']
                    self.instr_status[pc]['ExecStart'] = self.stats['cycles']
                    rs['exec_started'] = True

                    if op in ('add','addi','addiu','sub','add.d','sub.d'): ty2='add'
                    elif op in ('lw','ldc1'): ty2='load'
                    elif op in ('mul.d'): ty2='mult'
                    elif op in ('div.d'): ty2='div'
                    else: ty2='load'

                    rs['remaining'] = self.LAT[ty2]
                # execution countdown
                if rs['exec_started'] and rs['remaining'] > 0:
                    self.stats[f'{typ}_cycles'] += 1
                    rs['remaining'] -= 1
                    if rs['remaining'] == 0:
                        rs['ready'] = True
                        pc = rs['ins_addr']
                        self.instr_status[pc]['ExecComplete'] = self.stats['cycles']
                        # compute value
                        if typ == 'load' and rs['mem_addr'] is not None:
                            rs['value'] = self.memory[rs['mem_addr']]
                        elif typ == 'add':
                            vj = rs['Vj'] or 0
                            vk = rs['imm'] if op.startswith('addi') else (rs['Vk'] or 0)
                            rs['value'] = vj + vk
                        else:
                            rs['value'] = (rs['Vj'] or 0) * (rs['Vk'] or 0)

        # Issue stage
        if self.pending:
            addr = self.pending[0]
            ins = self.instrs[addr]
            op, args = ins['op'], ins['args']
            idx = lambda r: int(r[2:])
            if op != 'nop':
                mapping = {
                    'add':self.add_rs,'addi':self.add_rs,'sub':self.add_rs,
                    'add.d':self.add_rs,'sub.d':self.add_rs,
                    'mul.d':self.mult_rs,'div.d':self.mult_rs,
                    'lw':self.load_rs,'ldc1':self.load_rs,'sw':self.load_rs,'sdc1':self.load_rs
                }
                tgt_list = mapping.get(op, [])
                tgt = next((r for r in tgt_list if not r['busy']), None)
                if tgt:
                    producer = tgt['name']
                    self.next_tag += 1
                    tgt.update({'busy':True,'tag': producer,'addr':addr,'ins_addr':addr,'op':op})
                    self.instr_status[addr]['Issue'] = self.stats['cycles']
                    # set up operands and rename
                    if op in ('add','addi','sub'):
                        rd = idx(args[0]); rs1 = idx(args[1])
                        tgt['dst'] = rd
                        tgt['imm'] = ins.get('imm', 0)
                        # record src regs before rename
                        tgt['src_regs'] = [rs1] + ([idx(args[2])] if op == 'add' else [])
                        # RAW rename check
                        tgt['Vj'], tgt['Qj'] = (
                            (self.regs[rs1], None)
                            if self.rename_table[rs1] is None
                            else (None, self.rename_table[rs1])
                        )
                        if op == 'add':
                            rs2 = idx(args[2])
                            tgt['Vk'], tgt['Qk'] = (self.regs[rs2], None) if self.rename_table[rs2] is None else (None, self.rename_table[rs2])
                        # WAR detection: any other rs will read rd?
                        all_rs = self.load_rs + self.add_rs + self.mult_rs
                        war = any(
                            rd in rsu['src_regs']
                            for rsu in all_rs if rsu['busy'] and rsu is not tgt
                        )
                        if war:
                            self.stats['war_eliminated'] += 1
                        self.rename_table[rd] = producer
                    elif op in ('add.d','sub.d','mul.d','div.d'):
                        fd = idx(args[0]); fs = idx(args[1]); ft = idx(args[2])
                        tgt['dst'] = fd
                        tgt['src_regs'] = [fs, ft]
                        # similarly set Vj/Qj, Vk/Qk
                        tgt['Vj'], tgt['Qj'] = (self.fregs[fs], None) if self.frename_table[fs] is None else (None, self.frename_table[fs])
                        tgt['Vk'], tgt['Qk'] = (self.fregs[ft], None) if self.frename_table[ft] is None else (None, self.frename_table[ft])
                        # WAR detection on fd
                        all_rs = self.load_rs + self.add_rs + self.mult_rs
                        war = any(
                            fd in rsu['src_regs']
                            for rsu in all_rs if rsu['busy'] and rsu is not tgt
                        )
                        if war:
                            self.stats['war_eliminated'] += 1
                        self.frename_table[fd] = producer
                    # TODO: handle load/store src_regs and rename
            else:
                # nop: mark status immediately
                self.instr_status[addr] = {k: self.stats['cycles'] for k in self.instr_status[addr]}
            self.pending.pop(0)

    def rollback(self):
        if not self.history:
            return
        st = self.history.pop()
        (self.regs, self.rename_table,
         self.fregs, self.frename_table,
         (self.load_rs, self.add_rs, self.mult_rs),
         self.instr_status, self.pending,
         self.stats) = (
            st['regs'], st['rename'],
            st['fregs'], st['frename'],
            st['rs'], st['instr_status'], st['pending'],
            st['stats']
        )

    def reset(self):
        self.__init__(self.instr_list, self.LAT)

# ---------------- GUI ----------------
class App:
    def __init__(self, root):
        import tkinter.font as tkfont
        self.cpu = None
        self.instrs = None
        root.title("Tomasulo 模拟器")
        self.base_font = tkfont.Font(family='Microsoft YaHei', size=12)

        # latency inputs
        lat_frame = tk.LabelFrame(root, text='延迟设置(载入文件前设置)', font=self.base_font)
        lat_frame.grid(row=0, column=0, columnspan=2, sticky='ew')
        self.lat_entries = {}
        for label, default in [('add', 3), ('load', 2), ('mult', 4), ('div', 5)]:
            tk.Label(lat_frame, text=f"{label}:", font=self.base_font).pack(side=tk.LEFT)
            e = tk.Entry(lat_frame, width=3, font=self.base_font)
            e.insert(0, str(default))
            e.pack(side=tk.LEFT)
            self.lat_entries[label] = e

        # code textbox
        f1 = tk.LabelFrame(root, text='代码', font=self.base_font)
        f1.grid(row=1, column=0, sticky='nsew')
        self.txt_code = scrolledtext.ScrolledText(f1, font=self.base_font)
        self.txt_code.pack(fill=tk.BOTH, expand=True)

        # tables & stats display
        f2 = tk.LabelFrame(root, text='保留站表 | 指令状态表 | 寄存器表 | 性能统计 (由上而下)', font=self.base_font)
        f2.grid(row=1, column=1, sticky='nsew')
        self.txt_rs = scrolledtext.ScrolledText(f2, font=self.base_font, height=5)
        self.txt_rs.pack(fill=tk.BOTH, expand=True)
        self.txt_instr = scrolledtext.ScrolledText(f2, font=self.base_font, height=5)
        self.txt_instr.pack(fill=tk.BOTH, expand=True)
        self.txt_reg = scrolledtext.ScrolledText(f2, font=self.base_font, height=5)
        self.txt_reg.pack(fill=tk.BOTH, expand=True)
        self.txt_stats = scrolledtext.ScrolledText(f2, font=self.base_font, height=4)
        self.txt_stats.pack(fill=tk.BOTH, expand=True)

        # control buttons
        c = tk.Frame(root)
        c.grid(row=2, column=0, columnspan=2, sticky='ew')
        self.step_entry = tk.Entry(c, width=5, font=self.base_font)
        self.step_entry.pack(side=tk.LEFT)
        for txt, cmd in [("多步", self.multi_step), ("单步", self.step),
                         ("回退", self.rollback), ("运行结束", self.run_to_end),
                         ("重置", self.reset), ("加载 ASM", self.load)]:
            tk.Button(c, text=txt, command=cmd, font=self.base_font).pack(side=tk.LEFT)

    def load(self):
        path = filedialog.askopenfilename(filetypes=[('ASM', '*.asm *.s')])
        if not path:
            return
        with open(path, encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        self.instrs = parse_asm(txt)
        lat = {k: int(e.get()) for k, e in self.lat_entries.items()}
        self.cpu = TomasuloCPU(self.instrs, lat)
        self.refresh_all()

    def refresh_all(self):
        if not self.cpu:
            return
        self.txt_code.delete('1.0', tk.END)
        for ins in self.cpu.instr_list:
            line = ins['raw'] if ins['op'] == 'label' else f"{ins['addr']:04x}: {ins['raw']}"
            self.txt_code.insert(tk.END, line + "\n")
        # RS
        self.txt_rs.delete('1.0', tk.END)
        self.txt_rs.insert('1.0', "Name\tBusy\tOp\tVj\tVk\tQj\tQk\tA\n")
        for rs in (self.cpu.load_rs + self.cpu.add_rs + self.cpu.mult_rs):
            busy_str = 'yes' if rs['busy'] else 'no'
            op = rs.get('op', '')

            if rs.get('Qj') is None:
                vj_str = rs.get('Vj', None)
                qj_str = None
            else:
                vj_str = None
                qj_str = rs['Qj']
            if op in ('lw','ldc1','sw','sdc1'):
                vk_str = rs.get('imm', '')
                qk_str = None
            else:
                if rs.get('Qk') is None:
                    vk_str = rs.get('Vk', None)
                    qk_str = None
                else:
                    vk_str = None
                    qk_str = rs['Qk']

            if op in ('lw', 'ldc1', 'sw', 'sdc1'):
                if rs.get('mem_addr') is not None:
                    a_val = rs['mem_addr']
                else:
                    a_val = rs.get('imm', None)
            else:
                a_val = None
            self.txt_rs.insert(
                tk.END,
                f"{rs['name']}\t"
                f"{busy_str}\t"
                f"{op}\t"
                f"{vj_str}\t"
                f"{vk_str}\t"
                f"{qj_str}\t"
                f"{qk_str}\t"
                f"{a_val}\n"
            )

        # instr status
        self.txt_instr.delete('1.0', tk.END)
        self.txt_instr.insert('1.0', "Addr\t流出\t执行开始\t执行结束\t写结果\n")
        for a,st in sorted(self.cpu.instr_status.items()):
            self.txt_instr.insert(tk.END, f"{a:04x}\t{st['Issue']}\t{st['ExecStart']}\t{st['ExecComplete']}\t{st['WriteBack']}\n")
        # rename table
        self.txt_reg.delete('1.0', tk.END)
        self.txt_reg.insert('1.0', "Reg\tQi\n")
        for i in range(0, len(self.cpu.rename_table), 2):
            qi = self.cpu.frename_table[i]
            self.txt_reg.insert(
                tk.END,
                f"F{i:02d}\t{qi}\n"
            )
        # stats
        s = self.cpu.stats
        stats_str = (
            f"执行周期总数: {s['cycles']}\n"
            f"RAW 数(发生停顿): {s['raw_stalls']}\n"
            f"WAR 数(寄存器换名消除): {s['war_eliminated']}\n"
            f"Load 部件运行周期: {s['load_cycles']}\n"
            f"Add 部件运行周期: {s['add_cycles']}\n"
            f"Mult 部件运行周期: {s['mult_cycles']}\n"
        )
        self.txt_stats.delete('1.0', tk.END)
        self.txt_stats.insert(tk.END, stats_str)

    def step(self):
        if self.cpu:
            self.cpu.step()
            self.refresh_all()

    def multi_step(self):
        if not self.cpu:
            return
        try:
            n = int(self.step_entry.get())
        except:
            messagebox.showerror("错误", "请输入数字")
            return
        for _ in range(n): self.cpu.step()
        self.refresh_all()

    def rollback(self):
        if self.cpu:
            self.cpu.rollback()
            self.refresh_all()

    def run_to_end(self):
        if not self.cpu:
            return
        while self.cpu.pending or any(r['busy'] for r in (self.cpu.load_rs + self.cpu.add_rs + self.cpu.mult_rs)):
            self.cpu.step()
        self.refresh_all()

    def reset(self):
        if self.cpu:
            self.cpu.reset()
            self.refresh_all()

if __name__ == '__main__':
    root = tk.Tk()
    App(root)
    root.mainloop()
