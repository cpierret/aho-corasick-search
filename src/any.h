#pragma once

#include <typeinfo>
#include <algorithm>

namespace textsearch {

// based on http://www.two-sdg.demon.co.uk/curbralan/papers/ValuedConversions.pdf
// Kevin Henney article in Dr Dobbs

class any
{
public:
    any()
        : content(0)
    {
    }
    ~any()
    {
        delete content;
    }
    const std::type_info &type_info() const
    {
        return content
            ? content->type_info()
            : typeid(void);
    }
    any(const any &other)
        : content(other.content ? other.content->clone() : 0)
    {
    }
    template<typename value_type>
    any(const value_type &value)
        : content(new holder<value_type>(value))
    {
    }

    template<typename value_type>
    const value_type& getContent(value_type*)
    {
        return 
    }

    any &swap(any &rhs)
    {
        std::swap(content, rhs.content);
        return *this;
    }
    any &operator=(const any &rhs)
    {
        return swap(any(rhs));
    }
    template<typename value_type>
    any &operator=(const value_type &rhs)
    {
        return swap(any(rhs));
    }
private:
    class placeholder
    {
    public:
        virtual ~placeholder()
        {
        }
        virtual const std::type_info &
            type_info() const = 0;
        virtual placeholder *clone() const = 0;
    };
    template<typename value_type>
    class holder : public placeholder
    {
    public:
        holder(const value_type &value)
            : held(value)
        {
        }
        virtual const std::type_info &type_info() const
        {
            return typeid(value_type);
        }
        virtual placeholder *clone() const
        {
            return new holder(held);
        }
        const value_type held;
    };
    placeholder *content;
};

}
namespace std {
    // specialization of std::swap
    template<>
    void std::swap(textsearch::any& x, textsearch::any&y)
    {
        x.swap(y);
    }
}