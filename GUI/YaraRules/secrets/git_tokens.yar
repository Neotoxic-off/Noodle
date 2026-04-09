// severity: dangerous
rule Credential_GitHub_PAT {
    meta:
        description = "GitHub Personal Access Token (ghp_ / gho_ / ghs_ / github_pat_)"
    strings:
        $ghp   = "ghp_" ascii
        $gho   = "gho_" ascii
        $ghs   = "ghs_" ascii
        $ghr   = "ghr_" ascii
        $ghpat = "github_pat_" ascii
        $ghenv = "GITHUB_TOKEN" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_GitLab_Token {
    meta:
        description = "GitLab personal or project access token"
    strings:
        $gl1  = "glpat-" ascii
        $gl2  = "GITLAB_TOKEN" ascii
        $gl3  = "CI_JOB_TOKEN" ascii
        $gl4  = "GL_TOKEN" ascii
    condition:
        any of them
}

// severity: dangerous
rule Credential_Bitbucket_Token {
    meta:
        description = "Bitbucket app password or OAuth token"
    strings:
        $bb1 = "BITBUCKET_APP_PASSWORD" ascii
        $bb2 = "bitbucket.org" ascii
        $bb3 = "BITBUCKET_TOKEN" ascii
    condition:
        2 of them
}
