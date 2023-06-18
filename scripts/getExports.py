#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import os
import pefile

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Extracts exports from a PE.' )
        parser.add_argument( '-d', required = False, help = 'Path to original DLL on the target system', default='C:\\Windows\\System32', type = str )
        parser.add_argument( '-f', required = True, help = 'Path to the source DLL', type = str )
        parser.add_argument( '-o', required = True, help = 'Path to store the output', type = str )
        option = parser.parse_args()

        fwd_path = option.d.replace('\\','/')
        PeExe = pefile.PE( option.f )
        with open(option.o, "w") as outfile:
            outfile.write("EXPORTS\n")
            for export in PeExe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name:
                    outfile.write(f"    {export.name.decode()}={fwd_path}/{os.path.basename(option.f)[0:-4]}.{export.name.decode()} @{export.ordinal}\n")

    except Exception as e:
        print( '[!] error: {}'.format( e ) )
