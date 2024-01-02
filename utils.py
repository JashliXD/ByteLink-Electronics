def reshape(arr, len_=3):
    new_arr = []
    for i in range(0,len(arr), len_):
        new_arr.append(arr[i:i+len_])
    return new_arr


def trimmer(text, len_=5):
    if len(text) > len_:
        a = text[:len_].rstrip(' ') + '...'
        return a
    return text