// severity: safe
rule Framework_Qt {
    meta:
        description = "Qt framework binary"
    strings:
        $qt5 = "Qt5Core" ascii nocase
        $qt6 = "Qt6Core" ascii nocase
        $meta = "QMetaObject" ascii
        $obj  = "QObject" ascii
        $wgt  = "QWidget" ascii
        $app  = "QApplication" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_wxWidgets {
    meta:
        description = "wxWidgets GUI framework binary"
    strings:
        $wx1 = "wxWidgets" ascii
        $wx2 = "wxApp" ascii
        $wx3 = "wxFrame" ascii
        $wx4 = "wxDialog" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_MFC {
    meta:
        description = "Microsoft Foundation Classes (MFC) binary"
    strings:
        $mfc = "mfc" ascii nocase
        $afx = "AFX_" ascii
        $cwnd = "CWnd" ascii
        $cdoc = "CDocument" ascii
        $cfrm = "CFrameWnd" ascii
    condition:
        3 of them
}

// severity: safe
rule Framework_ATL {
    meta:
        description = "Active Template Library (ATL/COM) binary"
    strings:
        $atl1 = "ATL.dll" ascii nocase
        $atl2 = "ATL::CComObject" ascii
        $atl3 = "ATL::CWindow" ascii
        $comdll = "ATLCOMCLI" ascii
    condition:
        2 of them
}

// severity: safe
rule Framework_GTK {
    meta:
        description = "GTK+ / GLib binary"
    strings:
        $gtk1 = "gtk_init" ascii
        $gtk2 = "GTK_WIDGET" ascii
        $glib = "g_main_loop" ascii
        $gobject = "g_object_new" ascii
        $gimp = "gdk_" ascii
    condition:
        2 of them
}
