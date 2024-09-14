// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel@priv.nu>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#pragma once

#include <exception>

#include "ndppd.h"
#include "logger.h"

NDPPD_NS_BEGIN

class invalid_pointer : public std::exception {
public:
    invalid_pointer() throw() {};
};

template <class T>
class weak_ptr;

// This template class simplifies the usage of pointers. It's basically
// a reference-counting smart pointer that supports both weak and
// strong references.

template <typename T>
class ptr {
    template <typename U>
    friend class ptr;

    struct ptr_ref {
        T* ptr;
        int wc, sc;
    };

protected:
    bool _weak;

    ptr_ref* _ref;

    void acquire(ptr_ref* ref)
    {
        if (_ref) {
            release();
        }

        if (ref && !ref->sc) {
            throw new invalid_pointer;
        }

        if (_ref = ref) {
            if (_weak) {
                _ref->wc++;
            } else {
                _ref->sc++;
            }
        }
    }

    void acquire(void* ptr)
    {
        if (!ptr) return;

        _ref      = new ptr_ref();
        _ref->ptr = (T*)ptr;
        _ref->wc  = !!_weak;
        _ref->sc  = !_weak;
    }

    void release()
    {
        if (!_ref) {
            return;
        }

        //logger::debug()
        //    << "ptr::release() _ref=" << logger::format("%x", _ref)
        //    << ", _ref->wc=" << _ref->wc << ", _ref->sc=" << _ref->sc
        //    << ", _weak=" << (_weak ? "yes" : "no");

        if (_weak) {
            assert(_ref->wc > 0);
            _ref->wc--;
        } else {
            assert(_ref->sc > 0);
            if (!--_ref->sc && _ref->ptr) {
                T* ptr = _ref->ptr;
                _ref->ptr = 0;
                _ref->wc++;
                delete ptr;
                _ref->wc--;
            }
        }

        /*if (!_weak && !_ref->sc && _ref->ptr) {
            T* ptr = (T*)(_ref->ptr);
            _ref->ptr = 0;
            delete ptr;
        }*/

        if (!_ref->sc && !_ref->wc) {
            delete _ref;
        }

        _ref = 0;
    }

    template <class U>
    void acquire(const ptr<U>& ptr)
    {
        acquire(ptr._ref);
    }

public:
    ptr(bool weak = false) :
        _weak(weak), _ref(0)
    {
    }

    ptr(T* p, bool weak = false) :
        _weak(weak), _ref(0)
    {
        acquire(p);
    }

    ptr(const ptr<T>& p, bool weak = false) :
        _weak(weak), _ref(0)
    {
        acquire(p._ref);
    }

    ptr(const weak_ptr<T>& p, bool weak = false) :
        _weak(weak), _ref(0)
    {
        acquire(p._ref);
    }

    template <class U>
    ptr(const ptr<U>& p, bool weak = false) :
        _weak(weak), _ref(0)
    {
        T* x = (U*)0;
        acquire(p._ref);
    }

    template <class U>
    ptr(const weak_ptr<U>& p, bool weak = false) :
        _weak(weak), _ref(0)
    {
        T* x = (U*)0;
        acquire(p._ref);
    }

    ~ptr()
    {
        release();
    }

    void operator=(T* p)
    {
        acquire(p);
    }

    ptr<T>& operator=(const ptr<T>& p)
    {
        acquire(p);
        return* this;
    }

    bool operator==(const ptr<T>& other) const
    {
        return other._ref == _ref;
    }

    bool operator!=(const ptr<T>& other) const
    {
        return other._ref != _ref;
    }

    ptr<T>& operator!=(const ptr<T>& other)
    {
      _ref = other._ref;
        return *this;
    }

    bool is_null() const
    {
        return !_ref || !_ref->ptr;
    }

    T& operator*() const
    {
        return* get_pointer();
    }

    T* operator->() const
    {
        return get_pointer();
    }

    operator T*() const
    {
        return get_pointer();
    }

    operator bool() const
    {
        return !is_null();
    }

    void reset(T* p = 0)
    {
        acquire(p);
    }

    T* get_pointer() const
    {
        if (!_ref || !_ref->ptr) {
            throw new invalid_pointer;
        }

        return static_cast<T* >(_ref->ptr);
    }
};

template <typename T>
class weak_ptr : public ptr<T> {
public:
    weak_ptr() :
        ptr<T>(true)
    {
    }

    weak_ptr(T* p) :
        ptr<T>(p, true)
    {
    }

    weak_ptr(const ptr<T>& p) :
        ptr<T>(p, true)
    {
    }

    weak_ptr(const weak_ptr<T>& p) :
        ptr<T>(p, true)
    {
    }

    template <class U>
    weak_ptr(const ptr<U>& p) :
        ptr<T>(p, true)
    {
    }

    template <class U>
    weak_ptr(const weak_ptr<U>& p) :
        ptr<T>(p, true)
    {
    }

    weak_ptr<T>& operator=(const weak_ptr<T>& ptr)
    {
        ndppd::ptr<T>::operator=(ptr);
        return *this;
    }

};

NDPPD_NS_END
