rule JS_Execution_and_DOM_Sinks {
    meta:
        description = "Mendeteksi fungsi sink berbahaya di JavaScript (WSTG-CLNT-01 & CLNT-02)"
        
    strings:
        // 1. Execution Sinks (Target CLNT-02)
        $exec_eval        = /eval\s*\(/
        $exec_function    = /new\s+Function\s*\(/
        $exec_timeout     = /setTimeout\s*\(\s*['"`]/  // Mendeteksi jika parameter pertama berupa string literal
        $exec_interval    = /setInterval\s*\(\s*['"`]/

        // 2. DOM/HTML Sinks (Target CLNT-01)
        $dom_inner        = /\.innerHTML\s*=/
        $dom_outer        = /\.outerHTML\s*=/
        $dom_write        = /document\.write(ln)?\s*\(/

        // 3. Navigation Sinks (Target CLNT-04)
        $nav_href         = /\.href\s*=/
        $nav_assign       = /\.assign\s*\(/

    condition:
        // Rule ini akan memicu alert jika salah satu string di atas ditemukan
        any of them
}
