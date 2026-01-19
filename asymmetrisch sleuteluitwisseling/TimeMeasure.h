#ifndef TimeMeasure_HPP
#define TimeMeasure_HPP
#include <chrono>


class TimeMeasure {


public:
	typedef std::chrono::microseconds microseconds;

	TimeMeasure() {
		resetEvent();
	}

	void resetEvent() {
		start = std::chrono::high_resolution_clock::now();
	}

	microseconds endEvent() {
		auto end = std::chrono::high_resolution_clock::now();
		microseconds duration = std::chrono::duration_cast<microseconds>(end - start);
		total += duration;
		return duration;
	}

	microseconds getTotal() const {
		return total;
	}

private:
	microseconds total{ 0 };
	std::chrono::high_resolution_clock::time_point start;
};
#endif // !TimeMeasure_HPP

