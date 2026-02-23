package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "strings"
    "time"
    
    "github.com/google/go-github/v45/github"
    "golang.org/x/oauth2"
)

type TokenScanner struct {
    client     *github.Client
    ctx        context.Context
    cloneDir   string
    tokenRegex map[string]*regexp.Regexp
    httpClient *http.Client
}

type FoundToken struct {
    Type     string
    Token    string
    File     string
    Line     int
    Valid    bool
    Response string
}

func NewTokenScanner(token, cloneDir string) *TokenScanner {
    ctx := context.Background()
    ts := oauth2.StaticTokenSource(
        &oauth2.Token{AccessToken: token},
    )
    tc := oauth2.NewClient(ctx, ts)
    client := github.NewClient(tc)
    
    os.MkdirAll(cloneDir, 0755)
    
    return &TokenScanner{
        client:     client,
        ctx:        ctx,
        cloneDir:   cloneDir,
        httpClient: &http.Client{Timeout: 10 * time.Second},
        tokenRegex: map[string]*regexp.Regexp{
            "Discord Token": regexp.MustCompile(`[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}`),
            "GitHub Token":  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),
            "AWS Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
        },
    }
}

func (s *TokenScanner) SearchAndClone(query string, maxRepos int) error {
    fmt.Printf("\n🔍 Buscando: %s\n", query)
    
    result, _, err := s.client.Search.Repositories(s.ctx, query, &github.SearchOptions{
        Sort:  "updated",
        Order: "desc",
        ListOptions: github.ListOptions{
            PerPage: maxRepos,
        },
    })
    
    if err != nil {
        return err
    }
    
    fmt.Printf("📊 Total encontrado: %d\n", *result.Total)
    fmt.Printf("📦 Clonando %d repositórios...\n\n", len(result.Repositories))
    
    for i, repo := range result.Repositories {
        fmt.Printf("[%d/%d] ", i+1, len(result.Repositories))
        s.cloneAndScan(repo)
    }
    
    return nil
}

func (s *TokenScanner) cloneAndScan(repo *github.Repository) {
    repoPath := filepath.Join(s.cloneDir, strings.Replace(*repo.FullName, "/", "_", -1))
    
    fmt.Printf("📁 %s (⭐ %d)\n", *repo.FullName, repo.GetStargazersCount())
    
    // Clone or pull
    if _, err := os.Stat(repoPath); err == nil {
        fmt.Printf("   🔄 Atualizando...\n")
        cmd := exec.Command("git", "-C", repoPath, "pull")
        cmd.Run()
    } else {
        fmt.Printf("   ⬇️  Clonando...\n")
        cmd := exec.Command("git", "clone", "--depth", "1", *repo.CloneURL, repoPath)
        if err := cmd.Run(); err != nil {
            fmt.Printf("   ❌ Erro ao clonar: %v\n", err)
            return
        }
    }
    
    // Escaneia e VALIDA os tokens
    tokens := s.scanDirectory(repoPath)
    
    // Filtra só tokens VÁLIDOS
    var validTokens []FoundToken
    for _, t := range tokens {
        if t.Valid {
            validTokens = append(validTokens, t)
        }
    }
    
    if len(validTokens) > 0 {
        fmt.Printf("   🚨 ENCONTRADOS %d TOKENS VÁLIDOS!\n", len(validTokens))
        for _, t := range validTokens {
            fmt.Printf("     • %s: %s\n", t.Type, t.Token[:min(30, len(t.Token))])
            fmt.Printf("       📍 %s:%d\n", t.File, t.Line)
            fmt.Printf("       💬 %s\n", t.Response)
        }
    } else if len(tokens) > 0 {
        fmt.Printf("   ⚠️  Encontrados %d tokens, mas TODOS inválidos\n", len(tokens))
    } else {
        fmt.Printf("   ✅ Nenhum token encontrado\n")
    }
}

func (s *TokenScanner) scanDirectory(path string) []FoundToken {
    var tokens []FoundToken
    
    filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }
        
        // Ignora .git e arquivos grandes
        if strings.Contains(filePath, ".git") || info.Size() > 1024*1024 {
            return nil
        }
        
        // Extensões relevantes
        ext := strings.ToLower(filepath.Ext(filePath))
        relevantExts := map[string]bool{
            ".env": true, ".json": true, ".js": true, ".py": true, 
            ".go": true, ".yml": true, ".yaml": true, ".txt": true,
            ".cfg": true, ".conf": true, ".config": true,
        }
        if !relevantExts[ext] {
            return nil
        }
        
        content, err := os.ReadFile(filePath)
        if err != nil {
            return nil
        }
        
        text := string(content)
        lines := strings.Split(text, "\n")
        
        for lineNum, line := range lines {
            for tokenType, regex := range s.tokenRegex {
                matches := regex.FindAllString(line, -1)
                for _, match := range matches {
                    // Pula exemplos óbvios
                    if strings.Contains(line, "example") || 
                       strings.Contains(line, "your_") ||
                       strings.Contains(match, "000000") {
                        continue
                    }
                    
                    token := FoundToken{
                        Type:  tokenType,
                        Token: match,
                        File:  filePath,
                        Line:  lineNum + 1,
                    }
                    
                    // VALIDA o token
                    s.validateToken(&token)
                    tokens = append(tokens, token)
                }
            }
        }
        
        return nil
    })
    
    return tokens
}

func (s *TokenScanner) validateToken(token *FoundToken) {
    switch token.Type {
    case "Discord Token":
        s.validateDiscordToken(token)
    case "GitHub Token":
        s.validateGitHubToken(token)
    case "AWS Key":
        s.validateAWSKey(token)
    }
}

func (s *TokenScanner) validateDiscordToken(token *FoundToken) {
    // Testa o token na API do Discord
    req, _ := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
    req.Header.Set("Authorization", token.Token)
    
    resp, err := s.httpClient.Do(req)
    if err != nil {
        token.Valid = false
        token.Response = fmt.Sprintf("Erro: %v", err)
        return
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    
    if resp.StatusCode == 200 {
        token.Valid = true
        // Tenta extrair nome do usuário
        var user struct {
            Username string `json:"username"`
            ID       string `json:"id"`
        }
        if json.Unmarshal(body, &user) == nil {
            token.Response = fmt.Sprintf("✅ Válido! Usuário: %s (ID: %s)", user.Username, user.ID)
        } else {
            token.Response = "✅ Válido! (token ativo)"
        }
    } else {
        token.Valid = false
        token.Response = fmt.Sprintf("❌ Inválido: %s", resp.Status)
    }
}

func (s *TokenScanner) validateGitHubToken(token *FoundToken) {
    // Testa o token na API do GitHub
    req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
    req.Header.Set("Authorization", "token "+token.Token)
    req.Header.Set("User-Agent", "Token-Scanner")
    
    resp, err := s.httpClient.Do(req)
    if err != nil {
        token.Valid = false
        token.Response = fmt.Sprintf("Erro: %v", err)
        return
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    
    if resp.StatusCode == 200 {
        token.Valid = true
        var user struct {
            Login string `json:"login"`
            Name  string `json:"name"`
        }
        if json.Unmarshal(body, &user) == nil {
            token.Response = fmt.Sprintf("✅ Válido! Usuário: %s (%s)", user.Login, user.Name)
        } else {
            token.Response = "✅ Válido! (token ativo)"
        }
    } else {
        token.Valid = false
        token.Response = fmt.Sprintf("❌ Inválido: %s", resp.Status)
    }
}

func (s *TokenScanner) validateAWSKey(token *FoundToken) {
    // AWS é mais complexo, mas podemos testar o formato
    // Idealmente usaria a SDK da AWS, mas é mais pesado
    if len(token.Token) == 20 && strings.HasPrefix(token.Token, "AKIA") {
        // Formato parece correto, mas não temos como testar sem secret
        token.Valid = true
        token.Response = "⚠️ Formato AWS válido, mas precisa do Secret Key para testar"
    } else {
        token.Valid = false
        token.Response = "❌ Formato AWS inválido"
    }
}

func (s *TokenScanner) SearchAndValidate(query string, maxRepos int) {
    fmt.Printf("\n🔍 Buscando: %s\n", query)
    
    result, _, err := s.client.Search.Repositories(s.ctx, query, &github.SearchOptions{
        Sort:  "updated",
        Order: "desc",
        ListOptions: github.ListOptions{
            PerPage: maxRepos,
        },
    })
    
    if err != nil {
        fmt.Printf("Erro na busca: %v\n", err)
        return
    }
    
    fmt.Printf("📊 Total encontrado: %d\n", *result.Total)
    
    var allTokens []FoundToken
    
    for i, repo := range result.Repositories {
        fmt.Printf("\n[%d/%d] 📁 %s\n", i+1, len(result.Repositories), *repo.FullName)
        
        repoPath := filepath.Join(s.cloneDir, strings.Replace(*repo.FullName, "/", "_", -1))
        
        // Clone rápido
        cmd := exec.Command("git", "clone", "--depth", "1", *repo.CloneURL, repoPath)
        if err := cmd.Run(); err != nil {
            fmt.Printf("   ❌ Erro ao clonar: %v\n", err)
            continue
        }
        
        // Escaneia
        tokens := s.scanDirectory(repoPath)
        allTokens = append(allTokens, tokens...)
        
        // Mostra resultados do repo
        var valid []FoundToken
        for _, t := range tokens {
            if t.Valid {
                valid = append(valid, t)
            }
        }
        
        if len(valid) > 0 {
            fmt.Printf("   🚨 %d TOKENS VÁLIDOS!\n", len(valid))
            for _, t := range valid {
                fmt.Printf("     • %s: %.30s...\n", t.Type, t.Token)
                fmt.Printf("       📍 %s\n", t.Response)
            }
        } else if len(tokens) > 0 {
            fmt.Printf("   ⚠️  %d tokens encontrados (todos inválidos)\n", len(tokens))
        } else {
            fmt.Printf("   ✅ Nenhum token\n")
        }
        
        // Apaga pra economizar espaço
        os.RemoveAll(repoPath)
    }
    
    // Estatísticas finais
    var validCount int
    for _, t := range allTokens {
        if t.Valid {
            validCount++
        }
    }
    
    fmt.Printf("\n📊 RESUMO FINAL:\n")
    fmt.Printf("   Total tokens encontrados: %d\n", len(allTokens))
    fmt.Printf("   Tokens VÁLIDOS: %d\n", validCount)
    fmt.Printf("   Tokens INVÁLIDOS: %d\n", len(allTokens)-validCount)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func main() {
    token := os.Getenv("GITHUB_TOKEN")
    if token == "" {
        log.Fatal("❌ Erro: GITHUB_TOKEN não definido!")
    }
    
    scanner := NewTokenScanner(token, "clones_temp")
    
    fmt.Println("🔐 Scanner com VALIDAÇÃO DE TOKENS")
    fmt.Println("===================================")
    
    queries := []string{
        "discord token filename:.env",
        "discord bot token in:file",
        "github_token in:file",
    }
    
    for _, query := range queries {
        scanner.SearchAndValidate(query, 3) // Só 3 por query pra não gastar rate limit
        time.Sleep(2 * time.Second)
    }
}