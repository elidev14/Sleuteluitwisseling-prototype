#ifndef TimeMeasure_HPP
#define TimeMeasure_HPP
#include <chrono>
class TimeMeasure {


public:
	typedef std::chrono::microseconds microSeconds;

	TimeMeasure() {
		resetEvent();
	}

	void resetEvent() {
		start = std::chrono::high_resolution_clock::now();
	}

	microSeconds endEvent() {
		auto end = std::chrono::high_resolution_clock::now();
		microSeconds duration = std::chrono::duration_cast<microSeconds>(end - start);
		total += duration;
		return duration;
	}

	microSeconds getTotal() const {
		return total;
	}

private:
	microSeconds total{ 0 };
	std::chrono::high_resolution_clock::time_point start;
};
#endif // !TimeMeasure_HPP

