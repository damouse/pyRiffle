from functools import total_ordering


@total_ordering
class HierarchicalName(object):

    """
    Instances should be immutable.
    """

    # Subclasses should override these.
    SEPARATOR = '.'
    WILDCARD = '*'
    CASE_SENSITIVE = False

    def __init__(self, name):
        if isinstance(name, HierarchicalName):
            self.name = name.name
            # Names should be immutable, so we can share the list.
            self.parts = name.parts
        elif isinstance(name, list):
            self.name = self.SEPARATOR.join(name)
            self.parts = name
        else:
            self.name = self.__class__.cleanName(str(name))
            self.parts = self.name.split(self.SEPARATOR)

    #
    # Comparison operators
    #
    # Defines ordering for addresses.
    #
    # Example:
    # pd < pd.damouse < pd.damouse.aardvark < pd.damouse.kangaroo
    #

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return self.name != other.name

    def __lt__(self, other):
        if len(self) < len(other):
            return True
        elif len(self) > len(other):
            return False

        # Only if the addresses are the same length do we need to compare
        # each part.
        for i in range(len(self)):
            if self[i] < other[i]:
                return True
            elif self[i] > other[i]:
                return False

        # They are equal.
        return False

    #
    # Object representation
    #
    # An HierarchicalName object is identified by the string form.
    #

    def __str__(self):
        return self.name

    def __repr__(self):
        return "{}('{}')".format(self.__class__.__name__, self.name)

    def __hash__(self):
        return hash(self.name)

    def __nonzero__(self):
        return len(self.name) > 0

    #
    # Container methods
    #

    def __len__(self):
        return len(self.parts)

    def __getitem__(self, key):
        return self.parts[key]

    #
    # contains
    #
    # Test if something is a subdomain of this address.
    #
    # Example:
    # pd.damouse.aardvark in pd.damouse
    #

    def __contains__(self, other):
        if isinstance(other, basestring):
            other = self.__class__(other)

        # A subdomain should have a longer address.
        if len(other) < len(self):
            return False

        # Handle the case where the name ends with an empty part---should
        # behave like ending with a wildcard.
        matchLen = len(self)
        if matchLen > 0 and self[-1] == "":
            matchLen -= 1

        for i in range(matchLen):
            if self[i] != other[i] and self[i] != self.WILDCARD:
                return False

        return True

    #
    # getstate and setstate are for pickling/unpickling.
    #
    # We only need to store the address string, which can be split into its
    # individual parts.
    #

    def __getstate__(self):
        return self.name

    def __setstate__(self, state):
        self.name = state
        self.parts = state.split(self.SEPARATOR)

    def hasWildcard(self):
        return (self.WILDCARD in self.name)

    def pop(self):
        """
        Return a new address with the last part popped off.
        """
        return self.__class__(self[0:-1])

    def prefixMatch(self, other):
        """
        Return the length of the matching prefix of the address.

        Wildcards (*) are considered matching but not counted.
        If the addresses differ in at least one place, then None is
        returned instead.

        addr should be a list.

        Example:
        pd.damouse.* and pd.damouse.aardvark -> 2
        pd.damouse.aardvark and pd.lance.squirrel -> None
        * and pd.lance.squirrel -> 0
        """
        matchLen = 0
        checkLen = min(len(self), len(other))
        for i in range(checkLen):
            if self[i] == other[i]:
                matchLen += 1

            # If either address contains a wildcard at position i,
            # we will not count it, but we will keep going.
            elif self[i] != self.WILDCARD and other[i] != self.WILDCARD:
                return None

        return matchLen

    @classmethod
    def cleanName(cls, name):
        """
        Clean up name (convert character case).
        """
        if cls.CASE_SENSITIVE:
            return name
        else:
            return name.lower()


class Domain(HierarchicalName):
    SEPARATOR = '.'
    WILDCARD = '*'
    CASE_SENSITIVE = True

    def __add__(self, other):
        if isinstance(other, Action):
            # Domain + Action -> Endpoint
            return Endpoint(domain=self, action=other)
        elif isinstance(other, basestring):
            # Domain + string -> Domain
            return Domain(self.name + Domain.SEPARATOR + other)
        else:
            raise Exception("Add operation not implemented for Domain + {}".format(
                other.__class__.__name__))

    @staticmethod
    def isSubdomain(addr1, addr2):
        """
        Test if addr1 is a subdomain of addr2.

        Addresses can be passed as strings.
        """
        return addr1 in Domain(addr2)


# Address is deprecated!
class Address(Domain):
    pass


class Action(HierarchicalName):
    SEPARATOR = '/'
    WILDCARD = '*'
    CASE_SENSITIVE = True

    def __add__(self, other):
        if isinstance(other, basestring):
            # Domain + string -> Domain
            return Action(self.name + Action.SEPARATOR + other)
        else:
            raise Exception("Add operation not implemented for Action + {}".format(
                other.__class__.__name__))


class Endpoint(object):

    """
    An Endpoint consists of an Address and an Action.

    If name is provided, it will be parsed into its domain and action
    components.  Otherwise, if name is None, the given domain and action values
    will be used.

    Example:
    Endpoint("pd.damouse.aardvark/a/b/c")
      -> Address("pd.damouse.aardvark")
      -> Action("a/b/c")

    Endpoint("pd.damouse.aardvark")
      -> Address("pd.damouse.aardvark")
      -> no action
    """

    def __init__(self, name=None, domain=None, action=None):
        if name is None:
            self.domain = domain
            self.action = action
        else:
            parts = name.split(Action.SEPARATOR)
            self.domain = Domain(parts[0])
            if len(parts) > 1:
                self.action = Action(parts[1:])
            else:
                self.action = None

    def __add__(self, other):
        if isinstance(other, basestring):
            newAction = self.action + other
            return Endpoint(domain=self.domain, action=newAction)

        elif isinstance(other, Action):
            newAction = self.action + other
            return Endpoint(domain=self.domain, action=newAction)

    def __str__(self):
        if self.action is not None:
            return "{}/{}".format(str(self.domain), str(self.action))
        else:
            return str(self.domain)

    def __repr__(self):
        return "Endpoint('{}')".format(str(self))

    def hasWildcard(self):
        return self.domain.hasWildcard() or self.action.hasWildcard()

    #
    # contains
    #
    # Test if something is a subspace of this Endpoint.
    #
    # Example:
    # pd.damouse.aardvark/a in pd.damouse
    #

    def __contains__(self, other):
        if isinstance(other, basestring):
            other = self.__class__(other)

        # A subspace should have the same domain.
        if self.domain != other.domain:
            return False

        # The action should be a subaction of other
        return other.action in self.action
