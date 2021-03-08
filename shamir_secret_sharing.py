#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import string
from six import integer_types
from utilitybelt import int_to_charset, charset_to_int

from rfc_3526_groups import RFC_3526_GROUPS
from polynomials import random_polynomial, get_polynomial_points, modular_lagrange_interpolation




def secret_int_to_points(secret_int, point_threshold, num_points, prime=None):
    """ Split a secret (integer) into shares (pair of integers / x,y coords).

        Sample the points of a random polynomial with the y intercept equal to
        the secret int.
    """
    if point_threshold < 2:
        raise ValueError("Threshold must be >= 2.")
    if point_threshold > num_points:
        raise ValueError("Threshold must be < the total number of points.")
    if not prime:
        prime = get_large_enough_prime([secret_int, num_points])
    if not prime:
        raise ValueError("Error! Secret is too long for share calculation!")
    coefficients = random_polynomial(point_threshold-1, secret_int, prime)
    points = get_polynomial_points(coefficients, num_points, prime)
    return points


def points_to_secret_int(points, prime=None):
    """ Join int points into a secret int.

        Get the intercept of a random polynomial defined by the given points.
    """
    if not isinstance(points, list):
        raise ValueError("Points must be in list form.")
    for point in points:
        if not isinstance(point, tuple) and len(point) == 2:
            raise ValueError("Each point must be a tuple of two values.")
        if not (isinstance(point[0], integer_types) and
                isinstance(point[1], integer_types)):
            raise ValueError("Each value in the point must be an int.")
    x_values, y_values = zip(*points)
    if not prime:
        prime = get_large_enough_prime(y_values)
    free_coefficient = modular_lagrange_interpolation(0, points, prime)
    secret_int = free_coefficient  # the secret int is the free coefficient
    return secret_int


def point_to_share_string(point, charset):
    """ Convert a point (a tuple of two integers) into a share string - that is,
        a representation of the point that uses the charset provided.
    """
    # point should be in the format (1, 4938573982723...)
    if '-' in charset:
        raise ValueError('The character "-" cannot be in the supplied charset.')
    if not (isinstance(point, tuple) and len(point) == 2 and isinstance(point[0], integer_types) and isinstance(point[1], integer_types)):
        raise ValueError('Point format is invalid. Must be a pair of integers.')
    x, y = point
    x_string = int_to_charset(x, charset)
    y_string = int_to_charset(y, charset)
    share_string = x_string + '-' + y_string
    return share_string


def share_string_to_point(share_string, charset):
    """ Convert a share string to a point (a tuple of integers).
    """
    # share should be in the format "01-d051080de7..."
    if '-' in charset:
        raise ValueError('The character "-" cannot be in the supplied charset.')
    if not isinstance(share_string, str) and share_string.count('-') == 1:
        raise ValueError('Share format is invalid.')
    x_string, y_string = share_string.split('-')
    if (set(x_string) - set(charset)) or (set(y_string) - set(charset)):
        raise ValueError("Share has characters that aren't in the charset.")
    x = charset_to_int(x_string, charset)
    y = charset_to_int(y_string, charset)
    return (x, y)


class SecretSharer():
    """ Creates a secret sharer, which can convert from a secret string to a
        list of shares and vice versa. The splitter is initialized with the
        character set of the secrets and the character set of the shares that
        it expects to be dealing with.
    """
    secret_charset = string.hexdigits[0:16]
    share_charset = string.hexdigits[0:16]

    GROUP_PRIME = RFC_3526_GROUPS[14][1] # 2048-bit prime


    def __init__(self):
        pass

    @classmethod
    def split_secret(self, secret_int, share_threshold, num_shares):
        points = secret_int_to_points(secret_int, share_threshold, num_shares, prime=self.GROUP_PRIME)
        shares = []
        for point in points:
            shares.append(point_to_share_string(point, self.share_charset))
        return shares

    @classmethod
    def recover_secret(self, shares):
        points = []
        for share in shares:
            points.append(share_string_to_point(share, self.share_charset))
        secret_int = points_to_secret_int(points, prime=self.GROUP_PRIME)
        return secret_int
