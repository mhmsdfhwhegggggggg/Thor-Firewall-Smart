//! ThorQL Parser — converts query text into an Abstract Syntax Tree (AST).
//!
//! Supported grammar:
//!   SELECT <col>[, <col>]* | *
//!   FROM   <table>
//!   [JOIN  <table2> ON <left_key> = <right_key>]
//!   [WHERE <expr>]
//!
//! Expressions: col = 'val', col LIKE '%pat%', col > n, col < n,
//!              expr AND expr, expr OR expr, NOT expr, (expr)
//!
//! JOIN semantics: INNER JOIN between two virtual tables.
//! Keys may be qualified: `table.column` or unqualified: `column`.
//!
//! Examples:
//!   SELECT * FROM processes WHERE name = 'bash'
//!   SELECT processes.pid, connections.remote_ip
//!     FROM processes JOIN connections ON processes.pid = connections.pid
//!     WHERE connections.state = 'ESTABLISHED'

use std::fmt;

// ─── Value ────────────────────────────────────────────────────────────────────

/// A literal value that can appear in a WHERE expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s)   => write!(f, "'{}'", s),
            Value::Int(n)   => write!(f, "{}", n),
            Value::Float(n) => write!(f, "{}", n),
        }
    }
}

// ─── AST nodes ────────────────────────────────────────────────────────────────

/// Comparison operators.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
    Like,
    NotLike,
}

/// WHERE expression tree.
#[derive(Debug, Clone)]
pub enum Expr {
    Comparison {
        column: String,
        op:     Op,
        value:  Value,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// Projection: either all columns (`*`) or a named list.
#[derive(Debug, Clone)]
pub enum Projection {
    All,
    Columns(Vec<String>),
}

/// An INNER JOIN clause — one join supported per statement.
#[derive(Debug, Clone)]
pub struct JoinClause {
    /// Right-hand table to join against.
    pub table:     String,
    /// Join key from the LEFT table. May be `table.col` or bare `col`.
    pub left_key:  String,
    /// Join key from the RIGHT table. May be `table.col` or bare `col`.
    pub right_key: String,
}

/// A fully parsed ThorQL SELECT statement.
#[derive(Debug, Clone)]
pub struct SelectStatement {
    pub projection: Projection,
    /// Primary (left) table name.
    pub table:      String,
    /// Optional INNER JOIN clause.
    pub join:       Option<JoinClause>,
    /// Optional WHERE filter.
    pub condition:  Option<Expr>,
}

// ─── Tokeniser ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Select, From, Join, On, Where, And, Or, Not, Like,
    // Punctuation
    Star, Comma, LParen, RParen, Dot,
    // Operators
    Eq, NotEq, Gt, Lt, Gte, Lte,
    // Literals & identifiers
    Ident(String),
    StrLit(String),
    IntLit(i64),
    FloatLit(f64),
    Eof,
}

struct Tokenizer<'a> {
    src: &'a [char],
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(src: &'a [char]) -> Self { Self { src, pos: 0 } }

    fn peek(&self) -> Option<char> { self.src.get(self.pos).copied() }

    fn advance(&mut self) -> Option<char> {
        let c = self.src.get(self.pos).copied();
        self.pos += 1;
        c
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) { self.advance(); }
    }

    fn read_ident_or_kw(&mut self) -> Token {
        let start = self.pos - 1;
        while matches!(self.peek(), Some(c) if c.is_alphanumeric() || c == '_') {
            self.advance();
        }
        let word: String = self.src[start..self.pos].iter().collect();
        match word.to_uppercase().as_str() {
            "SELECT" => Token::Select,
            "FROM"   => Token::From,
            "JOIN"   => Token::Join,
            "ON"     => Token::On,
            "WHERE"  => Token::Where,
            "AND"    => Token::And,
            "OR"     => Token::Or,
            "NOT"    => Token::Not,
            "LIKE"   => Token::Like,
            _        => Token::Ident(word),
        }
    }

    fn read_str_lit(&mut self) -> Result<Token, ParseError> {
        let mut s = String::new();
        loop {
            match self.advance() {
                None       => return Err(ParseError("Unterminated string literal".into())),
                Some('\'') => break,
                Some('\\') => match self.advance() {
                    Some('\'') => s.push('\''),
                    Some('\\') => s.push('\\'),
                    Some('n')  => s.push('\n'),
                    Some('t')  => s.push('\t'),
                    Some(c)    => { s.push('\\'); s.push(c); }
                    None       => return Err(ParseError("Unterminated escape".into())),
                },
                Some(c) => s.push(c),
            }
        }
        Ok(Token::StrLit(s))
    }

    fn read_number(&mut self, first: char) -> Token {
        let mut s = String::new();
        s.push(first);
        let mut is_float = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                s.push(c); self.advance();
            } else if c == '.' && !is_float {
                // Lookahead: only consume '.' as decimal if followed by digit
                if self.src.get(self.pos + 1).map(|nc| nc.is_ascii_digit()).unwrap_or(false) {
                    is_float = true;
                    s.push(c); self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if is_float {
            Token::FloatLit(s.parse().unwrap_or(0.0))
        } else {
            Token::IntLit(s.parse().unwrap_or(0))
        }
    }

    fn next_token(&mut self) -> Result<Token, ParseError> {
        self.skip_whitespace();
        match self.advance() {
            None       => Ok(Token::Eof),
            Some('*')  => Ok(Token::Star),
            Some(',')  => Ok(Token::Comma),
            Some('(')  => Ok(Token::LParen),
            Some(')')  => Ok(Token::RParen),
            Some('.')  => Ok(Token::Dot),
            Some('\'') => self.read_str_lit(),
            Some('=')  => Ok(Token::Eq),
            Some('!') => {
                if self.peek() == Some('=') { self.advance(); Ok(Token::NotEq) }
                else { Err(ParseError(format!("Unexpected '!' at pos {}", self.pos))) }
            }
            Some('>') => {
                if self.peek() == Some('=') { self.advance(); Ok(Token::Gte) } else { Ok(Token::Gt) }
            }
            Some('<') => {
                if self.peek() == Some('=') { self.advance(); Ok(Token::Lte) } else { Ok(Token::Lt) }
            }
            Some(c) if c.is_alphabetic() || c == '_' => Ok(self.read_ident_or_kw()),
            Some(c) if c.is_ascii_digit() || c == '-' => Ok(self.read_number(c)),
            Some(c) => Err(ParseError(format!("Unexpected '{}' at pos {}", c, self.pos))),
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let done = tok == Token::Eof;
            tokens.push(tok);
            if done { break; }
        }
        Ok(tokens)
    }
}

// ─── Parser error ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ThorQL parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

// ─── Recursive-descent parser ─────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos:    usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self { Self { tokens, pos: 0 } }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let tok = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            Ok(())
        } else {
            Err(ParseError(format!("Expected {:?} but found {:?}", expected, self.peek())))
        }
    }

    /// Parse a possibly table-qualified identifier: `table.column` → `"table.column"`.
    fn read_qualified_ident(&mut self) -> Result<String, ParseError> {
        let name = match self.advance().clone() {
            Token::Ident(s) => s,
            tok => return Err(ParseError(format!("Expected identifier, got {:?}", tok))),
        };
        if self.peek() == &Token::Dot {
            self.advance(); // consume '.'
            let col = match self.advance().clone() {
                Token::Ident(s) => s,
                tok => return Err(ParseError(format!("Expected column after '.', got {:?}", tok))),
            };
            Ok(format!("{}.{}", name, col))
        } else {
            Ok(name)
        }
    }

    /// Parse a table name, handling parameterised forms: `files('/path')`.
    fn parse_table_name(&mut self) -> Result<String, ParseError> {
        let name = match self.advance().clone() {
            Token::Ident(s) => s,
            tok => return Err(ParseError(format!("Expected table name, got {:?}", tok))),
        };
        if self.peek() == &Token::LParen {
            self.advance(); // '('
            let mut arg = String::new();
            let mut depth = 1i32;
            loop {
                match self.peek().clone() {
                    Token::Eof => return Err(ParseError("Unclosed '(' in table name".into())),
                    Token::LParen  => { depth += 1; arg.push('('); self.advance(); }
                    Token::RParen  => {
                        depth -= 1; self.advance();
                        if depth == 0 { break; }
                        arg.push(')');
                    }
                    Token::StrLit(s) => {
                        arg.push('\''); arg.push_str(&s); arg.push('\'');
                        self.advance();
                    }
                    Token::Ident(s) => { arg.push_str(&s); self.advance(); }
                    Token::Dot     => { arg.push('.'); self.advance(); }
                    _ => { self.advance(); }
                }
            }
            return Ok(format!("{}({})", name, arg));
        }
        Ok(name)
    }

    fn parse_select(&mut self) -> Result<SelectStatement, ParseError> {
        self.expect(&Token::Select)?;
        let projection = self.parse_projection()?;
        self.expect(&Token::From)?;
        let table = self.parse_table_name()?;

        // Optional JOIN clause
        let join = if self.peek() == &Token::Join {
            self.advance(); // consume JOIN
            let right_table = self.parse_table_name()?;
            self.expect(&Token::On)?;
            let left_key  = self.read_qualified_ident()?;
            self.expect(&Token::Eq)?;
            let right_key = self.read_qualified_ident()?;
            Some(JoinClause { table: right_table, left_key, right_key })
        } else {
            None
        };

        let condition = if self.peek() == &Token::Where {
            self.advance();
            Some(self.parse_or_expr()?)
        } else {
            None
        };

        Ok(SelectStatement { projection, table, join, condition })
    }

    fn parse_projection(&mut self) -> Result<Projection, ParseError> {
        if self.peek() == &Token::Star {
            self.advance();
            return Ok(Projection::All);
        }
        let mut cols = Vec::new();
        loop {
            let col = self.read_qualified_ident()?;
            cols.push(col);
            if self.peek() == &Token::Comma { self.advance(); } else { break; }
        }
        if cols.is_empty() { return Err(ParseError("Empty column list".into())); }
        Ok(Projection::Columns(cols))
    }

    fn parse_or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and_expr()?;
        while self.peek() == &Token::Or {
            self.advance();
            let right = self.parse_and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        while self.peek() == &Token::And {
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.peek() == &Token::Not {
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(expr)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        if self.peek() == &Token::LParen {
            self.advance();
            let expr = self.parse_or_expr()?;
            self.expect(&Token::RParen)?;
            return Ok(expr);
        }

        let column = self.read_qualified_ident()?;

        let op = match self.advance().clone() {
            Token::Eq    => Op::Eq,
            Token::NotEq => Op::NotEq,
            Token::Gt    => Op::Gt,
            Token::Lt    => Op::Lt,
            Token::Gte   => Op::Gte,
            Token::Lte   => Op::Lte,
            Token::Like  => Op::Like,
            Token::Not   => {
                if self.peek() == &Token::Like { self.advance(); Op::NotLike }
                else { return Err(ParseError("Expected LIKE after NOT".into())); }
            }
            tok => return Err(ParseError(format!("Expected operator, got {:?}", tok))),
        };

        let value = match self.advance().clone() {
            Token::StrLit(s)  => Value::Str(s),
            Token::IntLit(n)  => Value::Int(n),
            Token::FloatLit(f) => Value::Float(f),
            tok => return Err(ParseError(format!("Expected literal value, got {:?}", tok))),
        };

        Ok(Expr::Comparison { column, op, value })
    }
}

// ─── Public entry-point ───────────────────────────────────────────────────────

/// Parse a ThorQL query string into a `SelectStatement` AST.
///
/// # Errors
/// Returns `ParseError` if the input is syntactically invalid.
pub fn parse(query: &str) -> Result<SelectStatement, ParseError> {
    let chars:  Vec<char> = query.chars().collect();
    let tokens = Tokenizer::new(&chars).tokenize()?;
    let mut parser = Parser::new(tokens);
    parser.parse_select()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_select_star() {
        let stmt = parse("SELECT * FROM processes").unwrap();
        assert_eq!(stmt.table, "processes");
        assert!(matches!(stmt.projection, Projection::All));
        assert!(stmt.condition.is_none());
        assert!(stmt.join.is_none());
    }

    #[test]
    fn parse_select_columns_where() {
        let stmt = parse("SELECT pid, name FROM processes WHERE name = 'bash'").unwrap();
        assert_eq!(stmt.table, "processes");
        if let Projection::Columns(cols) = &stmt.projection {
            assert_eq!(cols, &["pid", "name"]);
        } else { panic!("Expected Columns projection"); }
        assert!(stmt.condition.is_some());
    }

    #[test]
    fn parse_inner_join_qualified_keys() {
        let stmt = parse(
            "SELECT processes.pid, connections.remote_ip \
             FROM processes JOIN connections ON processes.pid = connections.pid \
             WHERE connections.state = 'ESTABLISHED'"
        ).unwrap();
        assert_eq!(stmt.table, "processes");
        let join = stmt.join.expect("JOIN clause must be present");
        assert_eq!(join.table,     "connections");
        assert_eq!(join.left_key,  "processes.pid");
        assert_eq!(join.right_key, "connections.pid");
        assert!(stmt.condition.is_some());
    }

    #[test]
    fn parse_inner_join_unqualified_keys() {
        let stmt = parse(
            "SELECT pid, remote_ip FROM processes JOIN connections ON pid = pid"
        ).unwrap();
        let join = stmt.join.expect("JOIN must be present");
        assert_eq!(join.left_key,  "pid");
        assert_eq!(join.right_key, "pid");
    }

    #[test]
    fn parse_join_with_where() {
        let stmt = parse(
            "SELECT * FROM processes JOIN connections ON processes.pid = connections.pid \
             WHERE connections.remote_port > 1024 AND processes.uid = 0"
        ).unwrap();
        assert!(stmt.join.is_some());
        assert!(matches!(stmt.condition, Some(Expr::And(_, _))));
    }

    #[test]
    fn parse_like_expr() {
        let stmt = parse("SELECT * FROM connections WHERE cmdline LIKE '%base64%'").unwrap();
        if let Some(Expr::Comparison { op, .. }) = stmt.condition {
            assert_eq!(op, Op::Like);
        } else { panic!("Expected LIKE comparison"); }
    }

    #[test]
    fn parse_not_like() {
        let stmt = parse("SELECT * FROM processes WHERE name NOT LIKE '%kworker%'").unwrap();
        if let Some(Expr::Comparison { op, .. }) = stmt.condition {
            assert_eq!(op, Op::NotLike);
        } else { panic!("Expected NOT LIKE"); }
    }

    #[test]
    fn parse_and_or() {
        let stmt = parse(
            "SELECT pid FROM processes WHERE name = 'nc' AND cmdline LIKE '%-e%'"
        ).unwrap();
        assert!(matches!(stmt.condition, Some(Expr::And(_, _))));
    }

    #[test]
    fn parse_error_missing_from() {
        assert!(parse("SELECT * WHERE x = 1").is_err());
    }

    #[test]
    fn parse_error_join_missing_on() {
        assert!(parse("SELECT * FROM processes JOIN connections").is_err());
    }

    #[test]
    fn parse_numeric_comparison() {
        let stmt = parse("SELECT * FROM connections WHERE remote_port > 1024").unwrap();
        if let Some(Expr::Comparison { op, value: Value::Int(1024), .. }) = stmt.condition {
            assert_eq!(op, Op::Gt);
        } else { panic!("Expected numeric Gt comparison"); }
    }

    #[test]
    fn parse_qualified_projection() {
        let stmt = parse(
            "SELECT processes.pid, connections.remote_ip \
             FROM processes JOIN connections ON processes.pid = connections.pid"
        ).unwrap();
        if let Projection::Columns(cols) = &stmt.projection {
            assert!(cols.contains(&"processes.pid".to_string()));
            assert!(cols.contains(&"connections.remote_ip".to_string()));
        } else { panic!("Expected Columns projection"); }
    }

    #[test]
    fn parse_not_expr() {
        let stmt = parse("SELECT * FROM processes WHERE NOT name = 'systemd'").unwrap();
        assert!(matches!(stmt.condition, Some(Expr::Not(_))));
    }

    #[test]
    fn parse_float_comparison() {
        let stmt = parse("SELECT * FROM processes WHERE score > 0.75").unwrap();
        if let Some(Expr::Comparison { op, value: Value::Float(f), .. }) = stmt.condition {
            assert_eq!(op, Op::Gt);
            assert!((f - 0.75).abs() < 1e-9);
        } else { panic!("Expected Float Gt comparison"); }
    }
}
