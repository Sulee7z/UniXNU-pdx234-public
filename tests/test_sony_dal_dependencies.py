import importlib.util
from pathlib import Path
import unittest
import uuid

SPEC=importlib.util.spec_from_file_location('dal',Path(__file__).resolve().parents[1]/'ci/sony_dal_dependencies.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


class DalDependencies(unittest.TestCase):
    def test_unconditional_driver_waits_for_dal(self):
        old=b'\x06\x08';new=M.require_dal(old)
        self.assertTrue(M.evaluate(old,set()))
        self.assertFalse(M.evaluate(new,set()))
        self.assertTrue(M.evaluate(new,{M.DAL}))

    def test_existing_conditions_are_not_weakened(self):
        a='157a5c45-21b2-43c5-ba7c-822fee5fe599'
        b='f4e5c7d0-d239-47cb-aacd-7f66ef763238'
        old=b'\x02'+uuid.UUID(a).bytes_le+b'\x02'+uuid.UUID(b).bytes_le+b'\x03\x08'
        new=M.require_dal(old)
        for mask in range(8):
            installed={g for i,g in enumerate([a,b,M.DAL]) if mask>>i&1}
            self.assertEqual(M.evaluate(new,installed),M.evaluate(old,installed) and M.DAL in installed)

    def test_bad_expressions_refused(self):
        for data in [b'',b'\x08',b'\x02',b'\x06\x03\x08',b'\x06\x08\x06']:
            with self.assertRaises(ValueError):M.require_dal(data)

    def test_each_power_prerequisite_is_required(self):
        for name,required in M.POWER_DEPENDENCIES.items():
            expression=M.require_protocols(b'\x06\x08',required)
            self.assertTrue(M.evaluate(expression,set(required)),name)
            for guid in required:
                self.assertFalse(M.evaluate(expression,set(required)-{guid}),name)

    def test_reverse_file_order_converges_without_cycle(self):
        providers={'DALSys':M.DAL,'HWIODxeDriver':M.HWIO,'NpaDxe':M.NPA,
                   'ClockDxe':M.CLOCK,'CmdDbDxe':M.CMDDB,'RpmhDxe':M.RPMH,'ULogDxe':M.ULOG}
        dependencies={**M.POWER_DEPENDENCIES,**M.ULOG_DEPENDENCIES}
        pending=['UsbConfigDxe','PmicDxe','ICBDxe','VcsDxe','RscDxe','RpmhDxe',
                 'ClockDxe','NpaDxe','ULogDxe','HWIODxeDriver','DALSys','CmdDbDxe']
        installed=set();order=[]
        while pending:
            ready=[n for n in pending if set(dependencies.get(n,())) <= installed
                   and (n not in M.CONSUMERS or M.DAL in installed)]
            self.assertTrue(ready,'dependency cycle')
            for n in ready:
                pending.remove(n);order.append(n)
                if n in providers:installed.add(providers[n])
        for n in ['PmicDxe','VcsDxe','ICBDxe']:
            self.assertLess(order.index('RpmhDxe'),order.index(n))
        self.assertLess(order.index('NpaDxe'),order.index('ClockDxe'))
        self.assertLess(order.index('ULogDxe'),order.index('NpaDxe'))

    def test_npa_waits_for_both_dal_and_ulog(self):
        expression=M.require_protocols(M.require_dal(b'\x06\x08'),M.ULOG_DEPENDENCIES['NpaDxe'])
        for installed in [set(),{M.DAL},{M.ULOG},{M.DAL,M.ULOG}]:
            self.assertEqual(M.evaluate(expression,installed),installed=={M.DAL,M.ULOG})

    def test_usb_waits_for_resource_providers(self):
        for name,required in M.USB_RESOURCE_DEPENDENCIES.items():
            expression=M.require_protocols(b'\x06\x08',required)
            self.assertTrue(M.evaluate(expression,set(required)))
            for guid in required:self.assertFalse(M.evaluate(expression,set(required)-{guid}),name)

    def test_usb_resource_order_has_no_cycle(self):
        dependencies={**M.POWER_DEPENDENCIES,**M.ULOG_DEPENDENCIES}
        dependencies.pop('RscDxe')
        for name,required in M.USB_RESOURCE_DEPENDENCIES.items():dependencies[name]=dependencies.get(name,())+required
        providers={'ULogDxe':{M.ULOG},'NpaDxe':{M.NPA},'ClockDxe':{M.CLOCK},
                   'RpmhDxe':{M.RPMH},'ICBDxe':{M.ICB},'PmicDxe':{M.PMIC_VERSION,M.PMIC_GPIO}}
        pending=list(reversed(list(dependencies)))+['ULogDxe'];installed={M.DAL,M.CMDDB,M.HWIO}
        while pending:
            ready=[name for name in pending if set(dependencies.get(name,()))<=installed]
            self.assertTrue(ready,'dependency cycle')
            for name in ready:pending.remove(name);installed.update(providers.get(name,set()))

if __name__=='__main__':unittest.main()
