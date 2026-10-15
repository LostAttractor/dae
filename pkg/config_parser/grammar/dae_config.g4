grammar dae_config;

// Fragments
fragment SAFE_ID_HEAD_CHAR: [a-zA-Z_] ;
fragment SAFE_NONID_HEAD_CHAR: [/\\^*.+0-9-] ;
fragment SAFE_INTERMEDIATE_CHAR: [=@$!#%] ;
fragment SAFE_CHAR: ( SAFE_ID_HEAD_CHAR | SAFE_NONID_HEAD_CHAR | SAFE_INTERMEDIATE_CHAR ) ;
fragment DOUBLE_QUOTE_STRING : '"' ( '\\"' | '\\\\' | '\\' ~["\\] | ~["\\] )* '"' ;
fragment SINGLE_QUOTE_STRING : '\'' ( '\\\'' | '\\\\' | '\\' ~['\\] | ~['\\] )* '\'' ;

// Tokens
WHITESPACE : [ \t\r\n]+ -> skip ; // skip spaces, tabs, newlines
COMMENT_BLOCK : '/*' .*? '*/' -> skip ;
COMMENT_LINE_SHARP : '#' .*? ( [\r\n]+ | EOF ) -> skip ;

ID : SAFE_ID_HEAD_CHAR SAFE_CHAR* ;
NON_ID : SAFE_NONID_HEAD_CHAR SAFE_CHAR* ;
QUOTE_STRING : DOUBLE_QUOTE_STRING | SINGLE_QUOTE_STRING ;

// Rules
start : expression* EOF;

literal
    : ID | NON_ID | QUOTE_STRING
    ;

expression
    : ID '{' (arrowExpression | declaration | standaloneFunction | literal | expression)* '}'
    ;

declaration
    : key=(ID | NON_ID | QUOTE_STRING) ':' functionPrototype ('&&' functionPrototype)* optAnnotation
    | key=(ID | NON_ID | QUOTE_STRING) ':' literal (',' literal)* optAnnotation
    ;

optAnnotation
    : '[' (annotationParameter (',' annotationParameter)*)? ']'
    | // empty
    ;

annotationParameter
    : parameter
    | ID ':' functionPrototype
    ;

functionPrototype
    : '!'? (ID | NON_ID | QUOTE_STRING) '(' (parameter (',' parameter)*)? ')'
    ;

parameter
    : ID ':' literal
    | literal
    ;

arrowExpression
    : arrowOperand '->' arrowOperand ('->' arrowOperand)*
    ;

arrowOperand
    : ID ':' functionPrototype ('&&' functionPrototype)* optAnnotation
    | functionPrototype ('&&' functionPrototype)* optAnnotation
    | literal
    ;

standaloneFunction
    : functionPrototype optAnnotation
    ;
