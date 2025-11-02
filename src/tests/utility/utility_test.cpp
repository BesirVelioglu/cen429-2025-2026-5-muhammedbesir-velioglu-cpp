/**
 * @file utility_test.cpp
 * @brief Comprehensive unit tests for Utility library (MathUtility class)
 * @author Test Suite Author
 * @date 2025
 * @version 1.0
 * 
 * @details This test file provides comprehensive unit test coverage for the Utility library,
 *          specifically focusing on the MathUtility class functionality. It includes tests
 *          for mathematical operations like mean, median, min/max calculations, and comparison functions.
 * 
 * @section test_categories Test Categories
 * - Mean calculation tests
 * - Median calculation tests (odd and even number of elements)
 * - Double comparison tests (less, greater, equal)
 * - Min/Max calculation tests
 * 
 * @section usage Usage
 * Run tests using GoogleTest framework:
 * @code
 * ./utility_tests
 * @endcode
 * 
 * @note Uncomment ENABLE_UTILITY_TEST to enable tests
 * @see mathUtility.h for API documentation
 */

//#define ENABLE_UTILITY_TEST

#include "gtest/gtest.h"
#include "../../utility/header/commonTypes.h"
#include "../../utility/header/mathUtility.h"

#include <fstream>
#include <sys/stat.h>
#include <cstdio>
#ifdef _WIN32
  #include <direct.h>
#elif __linux__
  #include <unistd.h>
#endif


using namespace Coruh::Utility;

/**
 * @brief Test fixture for MathUtility unit tests
 * @details Provides setup and teardown functionality for all test cases.
 *          Manages test data initialization and cleanup.
 */
class MathUtilityTest : public ::testing::Test {
 public:
  int a;  /**< Test integer variable */
 protected:
  /**
   * @brief Set up test environment before each test case
   * @details Initializes test data for each test
   */
  void SetUp() override {
    //Setup test data  /**< Initialize test data */
  }

  /**
   * @brief Clean up test environment after each test case
   * @details Cleans up test data after each test
   */
  void TearDown() override {
    // Clean up test data  /**< Clean up test data after test */
  }
};



/**
 * @brief Test mean calculation with positive numbers
 * @test Verifies that calculateMean correctly calculates the average of an array
 * @details Tests mean calculation with array [1.0, 2.0, 3.0, 4.0, 5.0]
 * @param data Array of test data values
 * @param datalen Length of the data array
 * @return Expected result: 3.0 (average of 1+2+3+4+5 = 15/5)
 */
TEST_F(MathUtilityTest, CalculateMean) {
  int b = this->a;  /**< Local test variable */
  // Test data  /**< Define test input data */
  const double data[] = { 1.0, 2.0, 3.0, 4.0, 5.0 };  /**< Array of test values for mean calculation */
  const int datalen = sizeof(data) / sizeof(data[0]);  /**< Length of the data array */
  // Perform the calculation  /**< Calculate mean value */
  double result = MathUtility::calculateMean(data, datalen);  /**< Calculated mean value */
  // Check the result  /**< Verify calculation result */
  EXPECT_DOUBLE_EQ(result, 3.0);  /**< Verify mean equals expected value */
}


/**
 * @brief Test median calculation with odd number of elements
 * @test Verifies that calculateMedian correctly calculates the median for odd-length arrays
 * @details Tests median calculation with array [1.0, 2.0, 3.0, 4.0, 5.0] (5 elements)
 * @param data Array of test data values
 * @param datalen Length of the data array (odd number)
 * @return Expected result: 3.0 (middle element)
 */
TEST_F(MathUtilityTest, CalculateMedianOdd) {
  // Test data  /**< Define test input data */
  const double data[] = { 1.0, 2.0, 3.0, 4.0, 5.0 };  /**< Array of 5 values (odd number) for median calculation */
  const int datalen = sizeof(data) / sizeof(data[0]);  /**< Length of the data array (5 elements) */
  // Perform the calculation  /**< Calculate median value */
  double result = MathUtility::calculateMedian(data, datalen);  /**< Calculated median value */
  // Check the result  /**< Verify calculation result */
  EXPECT_DOUBLE_EQ(result, 3.0);  /**< Verify median equals expected middle value */
}

/**
 * @brief Test median calculation with even number of elements
 * @test Verifies that calculateMedian correctly calculates the median for even-length arrays
 * @details Tests median calculation with array [1.0, 2.0, 3.0, 4.0] (4 elements)
 * @param data Array of test data values
 * @param datalen Length of the data array (even number)
 * @return Expected result: 2.5 (average of middle two elements: (2.0+3.0)/2)
 */
TEST_F(MathUtilityTest, CalculateMedianEven) {
  // Test data  /**< Define test input data */
  const double data[] = { 1.0, 2.0, 3.0, 4.0 };  /**< Array of 4 values (even number) for median calculation */
  const int datalen = sizeof(data) / sizeof(data[0]);  /**< Length of the data array (4 elements) */
  // Perform the calculation  /**< Calculate median value */
  double result = MathUtility::calculateMedian(data, datalen);  /**< Calculated median value */
  // Check the result  /**< Verify calculation result */
  EXPECT_DOUBLE_EQ(result, 2.5);  /**< Verify median equals expected average of middle two values */
}

/**
 * @brief Test double comparison when first value is less than second
 * @test Verifies that compareDouble returns -1 when val1 < val2
 * @details Tests comparison function with val1=2.0, val2=4.0
 * @param val1 First double value (2.0)
 * @param val2 Second double value (4.0)
 * @return Expected result: -1 (val1 < val2)
 */
TEST_F(MathUtilityTest, CompareDoubleLessTest) {
  // Test data  /**< Define test input data */
  const double val1 = 2.0;  /**< First value (smaller) */
  const double val2 = 4.0;  /**< Second value (larger) */
  // Perform the comparison  /**< Compare two values */
  int result = MathUtility::compareDouble(&val1, &val2);  /**< Comparison result */
  // Check the result  /**< Verify comparison result */
  EXPECT_EQ(result, -1);  /**< Verify result is -1 (val1 < val2) */
}

/**
 * @brief Test double comparison when first value is greater than second
 * @test Verifies that compareDouble returns 1 when val1 > val2
 * @details Tests comparison function with val1=4.0, val2=2.0
 * @param val1 First double value (4.0)
 * @param val2 Second double value (2.0)
 * @return Expected result: 1 (val1 > val2)
 */
TEST_F(MathUtilityTest, CompareDoubleGreaterTest) {
  // Test data  /**< Define test input data */
  const double val1 = 4.0;  /**< First value (larger) */
  const double val2 = 2.0;  /**< Second value (smaller) */
  // Perform the comparison  /**< Compare two values */
  int result = MathUtility::compareDouble(&val1, &val2);  /**< Comparison result */
  // Check the result  /**< Verify comparison result */
  EXPECT_EQ(result, 1);  /**< Verify result is 1 (val1 > val2) */
}

/**
 * @brief Test double comparison when values are equal
 * @test Verifies that compareDouble returns 0 when val1 == val2
 * @details Tests comparison function with val1=3.0, val2=3.0
 * @param val1 First double value (3.0)
 * @param val2 Second double value (3.0)
 * @return Expected result: 0 (val1 == val2)
 */
TEST_F(MathUtilityTest, CompareDoubleEqualTest) {
  // Test data  /**< Define test input data */
  const double val1 = 3.0;  /**< First value */
  const double val2 = 3.0;  /**< Second value (equal to first) */
  // Perform the comparison  /**< Compare two values */
  int result = MathUtility::compareDouble(&val1, &val2);  /**< Comparison result */
  // Check the result  /**< Verify comparison result */
  EXPECT_EQ(result, 0);  /**< Verify result is 0 (val1 == val2) */
}

/**
 * @brief Test min/max calculation with positive sorted array
 * @test Verifies that calculateMinMax correctly finds minimum and maximum values
 * @details Tests min/max calculation with array [1.0, 2.0, 3.0, 4.0, 5.0]
 * @param data Array of test data values (sorted)
 * @param datalen Length of the data array
 * @param min Output parameter for minimum value
 * @param max Output parameter for maximum value
 * @return Expected: min=1.0, max=5.0
 */
TEST_F(MathUtilityTest, CalculateMinMaxTest_1) {
  // Test data  /**< Define test input data */
  const double data[] = { 1.0, 2.0, 3.0, 4.0, 5.0 };  /**< Sorted array of positive values */
  const int datalen = sizeof(data) / sizeof(data[0]);  /**< Length of the data array */
  double min, max;  /**< Output variables for minimum and maximum values */
  // Perform the calculation  /**< Calculate min and max values */
  MathUtility::calculateMinMax(data, datalen, &min, &max);  /**< Calculate min and max values */
  // Check the result  /**< Verify calculation results */
  EXPECT_DOUBLE_EQ(min, 1.0);  /**< Verify minimum value is 1.0 */
  EXPECT_DOUBLE_EQ(max, 5.0);  /**< Verify maximum value is 5.0 */
}

/**
 * @brief Test min/max calculation with unsorted array including negative values
 * @test Verifies that calculateMinMax correctly finds minimum and maximum in unsorted array
 * @details Tests min/max calculation with array [3.14, 1.0, -2.5, 7.2, -5.0] (unsorted, with negatives)
 * @param data Array of test data values (unsorted with negative values)
 * @param datalen Length of the data array
 * @param min Output parameter for minimum value
 * @param max Output parameter for maximum value
 * @return Expected: min=-5.0, max=7.2
 */
TEST_F(MathUtilityTest, CalculateMinMaxTest_2) {
  double data[] = { 3.14, 1.0, -2.5, 7.2, -5.0 };  /**< Unsorted array with negative values */
  double min, max;  /**< Output variables for minimum and maximum values */
  MathUtility::calculateMinMax(data, sizeof(data) / sizeof(data[0]), &min, &max);  /**< Calculate min and max values */
  EXPECT_DOUBLE_EQ(min, -5.0);  /**< Verify minimum value is -5.0 */
  EXPECT_DOUBLE_EQ(max, 7.2);  /**< Verify maximum value is 7.2 */
}





/**
 * @brief The main function of the test program.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @return int The exit status of the program.
 */
int main(int argc, char **argv) {
#ifdef ENABLE_UTILITY_TEST
  ::testing::InitGoogleTest(&argc, argv);  /**< Initialize Google Test framework */
  return RUN_ALL_TESTS();  /**< Run all test cases and return exit status */
#else
  (void)argc;  /**< Suppress unused parameter warning */
  (void)argv;  /**< Suppress unused parameter warning */
  return 0;  /**< Return success if tests are disabled */
#endif
}
