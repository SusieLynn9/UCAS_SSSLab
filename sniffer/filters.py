"""Small recursive-descent display filter. Never evaluates Python or JavaScript."""
import re
import shlex

class FilterError(ValueError):
    pass

PROTOCOLS={'ethernet','vlan','arp','ip','ipv4','ip6','ipv6','tcp','udp','icmp','icmp6','icmpv6','http','dns','tls'}
FIELDS={'ip.addr','ip.src','ip.dst','ipv6.addr','tcp.port','udp.port','port','src.port','dst.port','length','info','process','pid','flow','protocol'}
NUMERIC={'tcp.port','udp.port','port','src.port','dst.port','length','pid','flow'}

def compile_filter(expression):
    if len(expression)>2048:raise FilterError('Filter is too long (max 2048 characters)')
    try:
        lex=shlex.shlex(expression,posix=True,punctuation_chars='()!<>=&|');lex.whitespace_split=True;lex.commenters='';tokens=list(lex)
        # shlex joins adjacent punctuation, e.g. !(. Keep comparisons together.
        tokens=[s for t in tokens for s in (re.findall(r'&&|\|\||==|!=|>=|<=|[()!<>=&|]',t) if t and all(c in '()!<>=&|' for c in t) else [t])]
    except ValueError as e:raise FilterError(str(e))
    if not tokens:return lambda p:True
    if len(tokens)>256:raise FilterError('Too many filter tokens')
    cursor=0
    def peek():return tokens[cursor] if cursor<len(tokens) else None
    def pop():
        nonlocal cursor
        if peek() is None:raise FilterError('Unexpected end of filter')
        t=tokens[cursor];cursor+=1;return t
    def values(p,key):
        if key in ('tcp.port','udp.port') and p.get('transport','').lower()!=key.split('.')[0]:return []
        if key in ('ip.addr','ipv6.addr'):return [p.get('src',''),p.get('dst','')]
        if key in ('tcp.port','udp.port','port'):return [p.get('sport'),p.get('dport')]
        return [p.get({'ip.src':'src','ip.dst':'dst','src.port':'sport','dst.port':'dport','flow':'flow_id'}.get(key,key))]
    def atom():
        t=pop();low=t.lower()
        if low in ('not','!'):
            f=atom();return lambda p:not f(p)
        if t=='(':
            f=orexpr()
            if pop()!=')':raise FilterError('Missing closing parenthesis')
            return f
        if low in PROTOCOLS:
            name={'ip':'ipv4','ip6':'ipv6','icmp6':'icmpv6'}.get(low,low)
            return lambda p:name in [v.lower() for v in p.get('layers',[])]
        if low not in FIELDS:raise FilterError(f'Unknown protocol/field: {t}')
        op=pop().lower()
        if op not in ('==','!=','>','<','>=','<=','contains'):raise FilterError(f'Invalid operator: {op}')
        v=pop()
        if low in NUMERIC:
            try:v=int(v)
            except ValueError:raise FilterError(f'{low} requires an integer')
            if v<0 or ('port' in low and v>65535):raise FilterError('Numeric value out of range')
            if op=='contains':raise FilterError('contains requires a text field')
        elif op not in ('==','!=','contains'):raise FilterError('Text fields support ==, !=, contains')
        def compare(p):
            vals=[x for x in values(p,low) if x is not None]
            if op=='!=':return bool(vals) and all(x!=v for x in vals)
            return any((x==v if op=='==' else v in str(x) if op=='contains' else x>v if op=='>' else x<v if op=='<' else x>=v if op=='>=' else x<=v) for x in vals)
        return compare
    def andexpr():
        f=atom()
        while peek() and peek().lower() in ('and','&&'):
            pop();g=atom();f=(lambda a,b:lambda p:a(p) and b(p))(f,g)
        return f
    def orexpr():
        f=andexpr()
        while peek() and peek().lower() in ('or','||'):
            pop();g=andexpr();f=(lambda a,b:lambda p:a(p) or b(p))(f,g)
        return f
    try:result=orexpr()
    except RecursionError:raise FilterError('Filter nesting is too deep')
    if peek() is not None:raise FilterError(f'Unexpected token: {peek()}')
    return result
