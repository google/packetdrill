This page provides a reference for the syntactic and lexical structure of the packetdrill scripting language.

# packetdrill Syntactic Structure #

You can find the latest version of the grammar in the `parser.output` file after using `make` to build packetdrill. Here is the grammar for the packetdrill scripting language, as of the time of writing (July 2013):

```
    0 $accept: script $end

    1 script: opt_options opt_init_command events

    2 opt_options: /* empty */
    3            | options

    4 options: option
    5        | options option

    6 option: option_flag '=' option_value

    7 option_flag: OPTION

    8 option_value: INTEGER
    9             | WORD
   10             | STRING
   11             | IP_ADDR

   12 opt_init_command: /* empty */
   13                 | init_command

   14 init_command: command_spec

   15 events: event
   16       | events event

   17 event: event_time action

   18 event_time: '+' time
   19           | time
   20           | '*'
   21           | time '~' time
   22           | '+' time '~' '+' time

   23 time: FLOAT
   24     | INTEGER

   25 action: packet_spec
   26       | syscall_spec
   27       | command_spec
   28       | code_spec

   29 packet_spec: tcp_packet_spec
   30            | udp_packet_spec
   31            | icmp_packet_spec

   32 tcp_packet_spec: direction opt_ip_info flags seq opt_ack opt_window opt_tcp_options

   33 udp_packet_spec: direction UDP '(' INTEGER ')'

   34 icmp_packet_spec: direction opt_icmp_echoed ICMP icmp_type opt_icmp_code opt_icmp_mtu

   35 icmp_type: WORD

   36 opt_icmp_code: /* empty */
   37              | WORD

   38 opt_icmp_echoed: /* empty */
   39                | '[' UDP '(' INTEGER ')' ']'
   40                | '[' seq ']'

   41 opt_icmp_mtu: /* empty */
   42             | MTU INTEGER

   43 direction: '<'
   44          | '>'

   45 opt_ip_info: /* empty */
   46            | '[' ip_ecn ']'

   47 ip_ecn: NO_ECN
   48       | ECT0
   49       | ECT1
   50       | ECT01
   51       | CE

   52 flags: WORD
   53      | '.'
   54      | WORD '.'
   55      | '-'

   56 seq: INTEGER ':' INTEGER '(' INTEGER ')'

   57 opt_ack: /* empty */
   58        | ACK INTEGER

   59 opt_window: /* empty */
   60           | WIN INTEGER

   61 opt_tcp_options: /* empty */
   62                | '<' tcp_option_list '>'
   63                | '<' ELLIPSIS '>'

   64 tcp_option_list: tcp_option
   65                | tcp_option_list ',' tcp_option

   66 opt_tcp_fast_open_cookie: /* empty */
   67                         | tcp_fast_open_cookie

   68 tcp_fast_open_cookie: WORD
   69                     | INTEGER

   70 tcp_option: NOP
   71           | EOL
   72           | MSS INTEGER
   73           | WSCALE INTEGER
   74           | SACKOK
   75           | SACK sack_block_list
   76           | TIMESTAMP VAL INTEGER ECR INTEGER
   77           | FAST_OPEN opt_tcp_fast_open_cookie

   78 sack_block_list: sack_block
   79                | sack_block_list sack_block

   80 sack_block: INTEGER ':' INTEGER

   81 syscall_spec: opt_end_time function_name function_arguments '=' expression opt_errno opt_note

   82 opt_end_time: /* empty */
   83             | ELLIPSIS time

   84 function_name: WORD

   85 function_arguments: '(' ')'
   86                   | '(' expression_list ')'

   87 expression_list: expression
   88                | expression_list ',' expression

   89 expression: ELLIPSIS
   90           | decimal_integer
   91           | hex_integer
   92           | WORD
   93           | STRING
   94           | STRING ELLIPSIS
   95           | binary_expression
   96           | array
   97           | sockaddr
   98           | msghdr
   99           | iovec
  100           | pollfd
  101           | linger

  102 decimal_integer: INTEGER

  103 hex_integer: HEX_INTEGER

  104 binary_expression: expression '|' expression

  105 array: '[' ']'
  106      | '[' expression_list ']'

  107 sockaddr: '{' SA_FAMILY '=' WORD ',' SIN_PORT '=' _HTONS_ '(' INTEGER ')' ',' SIN_ADDR '=' INET_ADDR '(' STRING ')' '}'

  108 msghdr: '{' MSG_NAME '(' ELLIPSIS ')' '=' ELLIPSIS ',' MSG_IOV '(' decimal_integer ')' '=' array ',' MSG_FLAGS '=' expression '}'

  109 iovec: '{' ELLIPSIS ',' decimal_integer '}'

  110 pollfd: '{' FD '=' expression ',' EVENTS '=' expression opt_revents '}'

  111 opt_revents: /* empty */
  112            | ',' REVENTS '=' expression

  113 linger: '{' ONOFF '=' INTEGER ',' LINGER '=' INTEGER '}'

  114 opt_errno: /* empty */
  115          | WORD note

  116 opt_note: /* empty */
  117         | note

  118 note: '(' word_list ')'

  119 word_list: WORD
  120          | word_list WORD

  121 command_spec: BACK_QUOTED

  122 code_spec: CODE
```


# packetdrill Lexical Structure #

You can find the latest version of the lexical structure of the packetdrill scripting language in the `lexer.l` file. Here is the lexical structure for the packetdrill scripting language, as of the time of writing (July 2013):


```
/* A regexp for C++ comments: */
cpp_comment     \/\/[^\n]*\n

/* Here is a summary of the regexp for C comments:
 *   open-comment
 *   any number of:
 *     (non-stars) or (star then non-slash)
 *   close comment
 */
c_comment       \/\*(([^*])|(\*[^\/]))*\*\/

/* The regexp for code snippets is analogous to that for C comments.
 * Here is a summary of the regexp for code snippets:
 *   %{
 *   any number of:
 *     (non-}) or (} then non-%)
 *   }%
 */
code            \%\{(([^}])|(\}[^\%]))*\}\%

/* A regular experssion for an IP address
 * TODO(ncardwell): IPv6
 */
ip_addr         [0-9]+[.][0-9]+[.][0-9]+[.][0-9]+

%%

sa_family               return SA_FAMILY;
sin_port                return SIN_PORT;
sin_addr                return SIN_ADDR;
msg_name                return MSG_NAME;
msg_iov                 return MSG_IOV;
msg_flags               return MSG_FLAGS;
fd                      return FD;
events                  return EVENTS;
revents                 return REVENTS;
onoff                   return ONOFF;
linger                  return LINGER;
htons                   return _HTONS_;
icmp                    return ICMP;
udp                     return UDP;
inet_addr               return INET_ADDR;
ack                     return ACK;
eol                     return EOL;
ecr                     return ECR;
mss                     return MSS;
mtu                     return MTU;
nop                     return NOP;
sack                    return SACK;
sackOK                  return SACKOK;
TS                      return TIMESTAMP;
FO                      return FAST_OPEN;
val                     return VAL;
win                     return WIN;
wscale                  return WSCALE;
ect01                   return ECT01;
ect0                    return ECT0;
ect1                    return ECT1;
noecn                   return NO_ECN;
ce                      return CE;
[.][.][.]               return ELLIPSIS;
--[a-zA-Z0-9_]+         yylval.string   = option(yytext); return OPTION;
[-]?[0-9]*[.][0-9]+     yylval.floating = atof(yytext);   return FLOAT;
[-]?[0-9]+              yylval.integer  = atoll(yytext);  return INTEGER;
0x[0-9]+                yylval.integer  = hextol(yytext); return HEX_INTEGER;
[a-zA-Z0-9_]+           yylval.string   = strdup(yytext); return WORD;
\"(\\.|[^"])*\"         yylval.string   = quoted(yytext); return STRING;
\`(\\.|[^`])*\`         yylval.string   = quoted(yytext); return BACK_QUOTED;
[^ \t\n]                return (int) yytext[0];
[ \t\n]+                /* ignore whitespace */;
{cpp_comment}           /* ignore C++-style comment */;
{c_comment}             /* ignore C-style comment */;
{code}                  yylval.string = code(yytext);   return CODE;
{ip_addr}               yylval.string = strdup(yytext); return IP_ADDR;
%%

```