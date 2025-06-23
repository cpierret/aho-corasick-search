#pragma once
#include <iterator>

template <typename functor_type, typename RandomAccessIterator,
          typename ValueType = typename std::iterator_traits<RandomAccessIterator>::value_type,
          typename DifferenceType = typename std::iterator_traits<RandomAccessIterator>::difference_type>
class functor_iterator {
        public:
                using iterator_category = std::random_access_iterator_tag;
                using value_type        = ValueType;
                using difference_type   = DifferenceType;
                using pointer           = value_type*;
                using reference         = value_type;
                value_type operator *() const { return f_(*i_); }
		const functor_iterator &operator ++() { ++i_; return *this; }
		const functor_iterator &operator --() { --i_; return *this; }
		functor_iterator operator ++(int) {
			functor_iterator copy(*this); ++i_; return copy;
		}
		functor_iterator operator --(int) {
			functor_iterator copy(*this); --i_; return copy;
		}

		bool operator ==(const functor_iterator &other) const { return i_ == other.i_; }
		bool operator !=(const functor_iterator &other) const { return i_ != other.i_; }
		bool operator  <(const functor_iterator &other) const { return i_< other.i_; }
		bool operator  >(const functor_iterator &other) const { return i_> other.i_; }
		bool operator  <=(const functor_iterator &other) const { return i_ <= other.i_; }
		bool operator  >=(const functor_iterator &other) const { return i_ >= other.i_; }

                functor_iterator operator +(const difference_type &add) const {
			functor_iterator copy(*this);
			copy.i_ = i_ + add;
			return copy;
		}
                functor_iterator & operator +=(const difference_type &add) {
			i_ = i_ + add;
			return *this;
		}
                functor_iterator operator -(const difference_type &add) const {
			functor_iterator copy(*this);
			copy.i_ = i_ - add;
			return copy;
		}
                functor_iterator & operator -=(const difference_type &add) {
			i_ = i_ - add;
			return *this;
		}
		ptrdiff_t operator -(const functor_iterator &other) const {
			return i_ - other.i_;
		}

		functor_iterator(functor_type& functor,RandomAccessIterator start) : i_(start),f_(functor) { }
		functor_iterator(const functor_iterator& other) : i_(other.i_), f_(other.f_) { }

		functor_iterator& operator=(const functor_iterator& other)
		{
			if (&other!=this)
			{
				this->i_ = other.i_;
				this->f_ = other.f_;
			}
			return *this;
		}
	private:
		RandomAccessIterator i_;
		functor_type& f_;
	};

class character_functor {
public:
	explicit character_functor(int (*charfunc)(int))
	{
		for (int i = 0; i < 256; ++i)
		{
			translations_[i] = static_cast<unsigned char>(charfunc(i));
		}
	}
	inline unsigned char operator()  (unsigned char c) { return translations_[c]; }
private:
	unsigned char translations_[256];
};
