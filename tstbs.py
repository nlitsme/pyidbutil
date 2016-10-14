def binary_search(a, k):
    # c++: a.upperbound(k)--
    first, last = 0, len(a)
    while first<last:
        mid = (first+last)>>1
        if k < a[mid]:
            last = mid
        else:
            first = mid+1
    return first-1
for x in range(8):
    print(x, binary_search([2,3,5,6], x))
