#!/usr/bin/env python

import re
import sys

IDENTIFIER_REGEX = "[a-zA-Z_][a-zA-Z0-9_]+"
CPP_QUALIFIED_NAME_REGEX = "%s(::%s)*" % (IDENTIFIER_REGEX,
                                          IDENTIFIER_REGEX)
string_replace = [
    ("std::__1", "std"),
    ("std::basic_string<char, std::char_traits<char>, std::allocator<char> >", "std::string"),
    ("std::basic_ostringstream<char, std::char_traits<char>, std::allocator<char> >",  "std::basic_ostringstream"),
    ("std::basic_stringbuf<char, std::char_traits<char>, std::allocator<char> >", "std::stringbuf"),
    ("std::basic_istream<char, std::char_traits<char> >", "std::istream"),
    ("std::basic_ostream<char, std::char_traits<char> >", "std::ostream"),
    ("std::basic_iostream<char, std::char_traits<char> >", "std::iostream"),
]

pairs = [(ord('<'), ord('>')), (ord('('), ord(')')), (ord('['), ord(']')),
         (ord('{'), ord('}'))]

def dump_string_as_array_of_chars(s):
    for (i, c) in enumerate(s):
        print '[%u] %s' % (i, c)


class string_range:
    def __init__(self, start, end):
        self.start = start
        self.end = end


def get_amount_and_index(ch):
    global pairs
    for (i, cp) in enumerate(pairs):
        if ch == cp[0]:
            return (+1, i)
        if ch == cp[1]:
            return (-1, i)
    return (0, 0)


def find_matching_char(s, pos):
    '''Given a string and a position that points to a starting character in
    "char_pairs", find the matching terminating character of the character
    pair'''
    ai = get_amount_and_index(ord(s[pos]))
    if ai[0] == +1:
        counts = list()
        for i in range(len(pairs)):
            counts.append(0)
        counts[ai[1]] += ai[0]
        for i in range(pos + 1, len(s)):
            ai = get_amount_and_index(ord(s[i]))
            if ai[0]:
                counts[ai[1]] += ai[0]
                done = True
                for c in counts:
                    if c != 0:
                        done = False
                if done:
                    return i
    return -1


def find_cpp_arg_end(s, pos, end_pos):
    global pairs
    while pos < end_pos:
        pos_adjusted = False
        ch = ord(s[pos])
        if ch == ord(','):
            return pos
        for cp in pairs:
            if ch == cp[0]:
                pos = find_matching_char(s, pos)
                if pos == -1:
                    return -1
                pos += 1
                pos_adjusted = True
                break
            if ch == cp[1]:
                print 'unexpected %c character at index %u of "%s"' % (ch, pos,
                                                                       s)
                return -1
        if not pos_adjusted:
            pos += 1
    return pos


class template_splitter:
    def __init__(self, s):
        self.s = s
        self.name = None
        self.params = list()
        self.template_start = -1
        self.template_end = -1
        template_start_re = re.compile("(%s)(<)" % (CPP_QUALIFIED_NAME_REGEX))
        m = template_start_re.search(s)
        if m:
            self.template_start = m.start(3)
            self.template_end = find_matching_char(s, self.template_start)
            if self.template_end > 0:
                self.name = string_range(m.start(1), m.end(1))
            arg_start = self.template_start + 1
            while arg_start < self.template_end:
                arg_end = find_cpp_arg_end(s, arg_start, self.template_end)
                if arg_end == -1:
                    print 'error: unexpected arg end not found'
                while s[arg_start].isspace():
                    arg_start += 1
                while s[arg_end-1].isspace():
                    arg_end -= 1
                self.params.append(string_range(arg_start, arg_end))
                arg_start = arg_end + 1

    def dump(self, f=sys.stdout):
        name = self.get_name()
        if name:
            print 'name: "%s"' % (name)
            for idx in range(self.get_num_params()):
                num = idx + 1
                name = self.get_param(num)
                print 'param%u = "%s"' % (num, name)

    def get_substr(self, range):
        return self.s[range.start:range.end]

    def get_name(self):
        if self.name is None:
            return None
        return self.get_substr(self.name)

    def get_num_params(self):
        return len(self.params)

    def get_param(self, number):
        '''Parameter number starts at 1.'''
        idx = number - 1
        if idx >= 0 and idx < len(self.params):
            return self.get_substr(self.params[idx])
        return None

    @classmethod
    def shorten(cls, s):
        debug = False
        remaining = s
        result = None
        while True:
            if debug:
                print 'remaining = "%s"' % (remaining)
            t = template_splitter(remaining)
            if t.name is None:
                processed = remaining
                remaining = None
            else:
                if debug:
                    t.dump()
                (processed, remaining) = t.__shorten_template()
            if debug:
                print 'processed = "%s"' % (processed)
            if result:
                result += processed
            else:
                result = processed
            if remaining is None or len(remaining) == 0:
                return result

    def __shorten_template(self):
        default_allocator_2 = ['std::vector', 'std::__vector_base', 'std::__split_buffer']
        name = self.get_name()
        result = None
        if name == 'std::map' or name == 'std::multimap':
            result = self.__shorten_std_map()
        if name in default_allocator_2:
            result = self.__shorten_template_with_default_allocator()
        if result is None:
            return (self.s[0:self.template_end+1], self.s[self.template_end+1:])
        else:
            return result

    def __shorten_template_with_default_allocator(self):
        '''If the template is a template with a second argument that is an
        allocator, we can remove the allocator. For example:
            std::vector<std::string, std::allocator<std::string > >::~vector()
        Can be shortened to:
            std::vector<std::string>::~vector()
        '''
        debug = False
        if debug:
            print 'template with default allocator as arg2: "%s"' % (self.s)
        num_params = self.get_num_params()
        if num_params != 2:
            return None
        allocator = template_splitter(self.get_param(2))
        if debug:
            allocator.dump()
        if allocator.get_name() != 'std::allocator':
            return None
        if self.get_param(1) != allocator.get_param(1):
            return None
        remove_start = self.params[0].end
        remove_end = self.params[1].end
        if self.s[remove_end] == ' ':
            remove_end += 1
        end = self.template_end+1
        short = self.s[0:remove_start] + self.s[remove_end:end]
        if debug:
            print 'default allocator can be shortened: "%s"' % (short)
        return (short, self.s[end:])

    def __shorten_std_map(self):
        '''If the template is a std::map or std::multimap and can be shortened
        return a shortened string, else return None'''
        debug = False
        if debug:
            print 'std::map template: "%s"' % (self.s)
        num_params = self.get_num_params()
        if num_params != 4:
            return None
        comparison = template_splitter(self.get_param(3))
        if comparison.get_name() != "std::less":
            return None
        if debug:
            comparison.dump()
        if comparison.get_num_params() != 1:
            return None
        param1 = self.get_param(1)
        if comparison.get_param(1) != param1:
            return None
        if debug:
            print 'std::less is default'
        allocator = template_splitter(self.get_param(4))
        if debug:
            allocator.dump()
        if allocator.get_name() != 'std::allocator':
            return None
        pair = template_splitter(allocator.get_param(1))
        if debug:
            pair.dump()
        pair_first = pair.get_param(1)
        if not (pair_first == param1 or pair_first == param1 + " const"):
            return None
        pair_second = pair.get_param(2)
        if pair_second != self.get_param(2):
            return None
        remove_start = self.params[1].end
        remove_end = self.params[3].end+1
        end = self.template_end+1
        short = self.s[0:remove_start] + self.s[remove_end:end]
        if debug:
            print 'std::map can be shortened: "%s"' % (short)
        return (short, self.s[end:])


def shorten_string(s):
    global string_replace
    for r in string_replace:
        s = s.replace(r[0], r[1])
    short = template_splitter.shorten(s)
    if short:
        return short
    return s


def main():
    # strs = ["FUNC a260 33 0 std::__split_buffer<AA, std::allocator<AA>&>::clear()", "FUNC a260 33 0 std::__split_buffer<AA, std::allocator<AA> >::clear()"]
    # for s in strs:
    #     print 'orig = "%s"' % (s)
    #     s = shorten_string(s)
    #     print 'sstr = "%s"' % (s)
    #     short = template_splitter.shorten(s)
    #     print 'tmpl = "%s"' % (short)
    # return
    paths = sys.argv[1:]
    for path in paths:
        f = open(path, 'r')
        lines = f.readlines()
        n_lines = len(lines)
        for i in range(n_lines):
            line = shorten_string(lines[i])
            print line,


if __name__ == '__main__':
    main()
