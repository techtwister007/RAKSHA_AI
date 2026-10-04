# Fleet — sister codebases for the Vulnerability Vaccine sweep

Three small services from the same (fictional) estate as `py-cmdinject`. Two repeat its mistake —
user input reaching a `shell=True` subprocess — in different shapes; one already does it safely.
A rule mined from the verified `py-cmdinject` fix must find the two and leave the third alone.
