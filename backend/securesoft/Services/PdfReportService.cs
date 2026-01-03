using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SkiaSharp;
using ComplianceSecurityAuditor.Models;

namespace ComplianceSecurityAuditor.Services
{
    public class PdfReportService
    {
        public PdfReportService()
        {
            // Configure license
            QuestPDF.Settings.License = LicenseType.Community;
        }

        public byte[] GenerateNetworkReport(NetworkScanResult result)
        {
             var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Margin(50);
                    page.Size(PageSizes.A4);
                    page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Arial"));

                    page.Header().Element(c => ComposeNetworkHeader(c, result));
                    
                    page.Content().PaddingVertical(20).Column(column =>
                    {
                        column.Spacing(20);

                        // 1. Overview
                        column.Item().Element(c => ComposeNetworkOverview(c, result));

                        // 2. Open Ports
                        column.Item().Element(c => ComposeOpenPorts(c, result));

                        // 3. Security Headers
                        column.Item().Element(c => ComposeSecurityHeaders(c, result));

                        // 4. PII Findings
                        column.Item().Element(c => ComposePiiFindings(c, result));
                    });

                    page.Footer().AlignCenter().Text(x =>
                    {
                        x.Span("Page ");
                        x.CurrentPageNumber();
                        x.Span(" of ");
                        x.TotalPages();
                    });
                });
            });

            return document.GeneratePdf();
        }

        void ComposeNetworkHeader(IContainer container, NetworkScanResult result)
        {
            var titleStyle = TextStyle.Default.FontSize(24).SemiBold().FontColor(Colors.Blue.Medium);

            container.Row(row =>
            {
                row.RelativeItem().Column(column =>
                {
                    column.Item().Text("Network Security Audit").Style(titleStyle);
                    column.Item().Text(text =>
                    {
                        text.Span("Target: ").SemiBold();
                        text.Span(result.Url);
                    });
                    column.Item().Text(text =>
                    {
                        text.Span("Scan Date: ").SemiBold();
                        text.Span($"{result.CreatedAt:g}");
                    });
                });
            });
        }

        void ComposeNetworkOverview(IContainer container, NetworkScanResult result)
        {
            container.Column(column =>
            {
                column.Item().Text("Executive Summary").FontSize(16).SemiBold().FontColor(Colors.Grey.Darken2);
                column.Item().PaddingTop(5).Text($"Security Score: {result.SecurityScore}/100").FontSize(14).Bold()
                    .FontColor(result.SecurityScore >= 90 ? Colors.Green.Medium : result.SecurityScore < 60 ? Colors.Red.Medium : Colors.Orange.Medium);
                
                column.Item().PaddingTop(5).Text($"Status: {result.StatusCode} {result.StatusReason}");
            });
        }

        void ComposeOpenPorts(IContainer container, NetworkScanResult result)
        {
            container.Column(column =>
            {
                column.Item().Text("Open Ports & Services").FontSize(16).SemiBold().FontColor(Colors.Grey.Darken2);
                
                if (result.OpenPorts.Count == 0)
                {
                    column.Item().PaddingTop(5).Text("No common open ports detected.");
                }
                else
                {
                    foreach (var port in result.OpenPorts)
                    {
                        column.Item().PaddingTop(2).Text($"• Port {port} (OPEN) - Potential exposure point.");
                    }
                }
            });
        }

        void ComposeSecurityHeaders(IContainer container, NetworkScanResult result)
        {
            container.Column(column =>
            {
                column.Item().Text("Security Headers").FontSize(16).SemiBold().FontColor(Colors.Grey.Darken2);
                
                if (result.MissingSecurityHeaders.Count == 0)
                {
                    column.Item().PaddingTop(5).Text("All critical security headers are present.").FontColor(Colors.Green.Medium);
                }
                else
                {
                    foreach (var header in result.MissingSecurityHeaders)
                    {
                        column.Item().PaddingTop(2).Text($"• Missing: {header}").FontColor(Colors.Red.Medium);
                    }
                }
            });
        }

        void ComposePiiFindings(IContainer container, NetworkScanResult result)
        {
            container.Column(column =>
            {
                column.Item().Text("PII & Sensitive Data").FontSize(16).SemiBold().FontColor(Colors.Grey.Darken2);
                
                if (result.PiiFindings.Count == 0)
                {
                    column.Item().PaddingTop(5).Text("No PII patterns detected in public response.");
                }
                else
                {
                    foreach (var finding in result.PiiFindings)
                    {
                        column.Item().PaddingTop(2).Text($"• {finding}").FontColor(Colors.Red.Medium);
                    }
                }
            });
        }

        public byte[] GenerateReport(ScanStatistics stats)
        {
            var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Margin(50);
                    page.Size(PageSizes.A4);
                    page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Arial"));

                    page.Header().Element(ComposeHeader);
                    
                    page.Content().PaddingVertical(20).Column(column =>
                    {
                        column.Spacing(20);

                        // 1. Executive Summary
                        column.Item().Element(c => ComposeSummary(c, stats));

                        // 2. Charts Section
                        column.Item().Element(c => ComposeCharts(c, stats));

                        // 3. Top Violations Section
                        column.Item().PageBreak(); // Start on new page
                        column.Item().Element(c => ComposeTopViolations(c, stats));
                    });

                    page.Footer().AlignCenter().Text(x =>
                    {
                        x.Span("Page ");
                        x.CurrentPageNumber();
                        x.Span(" of ");
                        x.TotalPages();
                    });
                });
            });

            return document.GeneratePdf();
        }

        void ComposeHeader(IContainer container)
        {
            var titleStyle = TextStyle.Default.FontSize(24).SemiBold().FontColor(Colors.Blue.Medium);

            container.Row(row =>
            {
                row.RelativeItem().Column(column =>
                {
                    column.Item().Text("SecureSoft Audit Report").Style(titleStyle);
                    column.Item().Text(text =>
                    {
                        text.Span("Generated on: ").SemiBold();
                        text.Span($"{DateTime.Now:g}");
                    });
                });
            });
        }

        void ComposeSummary(IContainer container, ScanStatistics stats)
        {
            container.Column(column =>
            {
                column.Item().Text("Executive Summary").FontSize(18).SemiBold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(10).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.RelativeColumn();
                        columns.RelativeColumn();
                        columns.RelativeColumn();
                        columns.RelativeColumn();
                    });

                    table.Header(header =>
                    {
                        header.Cell().Element(CellStyle).Text("Files Scanned");
                        header.Cell().Element(CellStyle).Text("Total Violations");
                        header.Cell().Element(CellStyle).Text("Scan Duration");
                        header.Cell().Element(CellStyle).Text("Risk Score");
                    });

                    table.Cell().Element(CellStyle).Text(stats.FilesScanned.ToString());
                    table.Cell().Element(CellStyle).Text(stats.ViolationsFound.ToString()).FontColor(Colors.Red.Medium).Bold();
                    table.Cell().Element(CellStyle).Text($"{stats.ScanDuration:F2}s");
                    
                    // Simple risk score logic
                    var riskScore = stats.ViolationsFound > 100 ? "Critical" : stats.ViolationsFound > 20 ? "High" : "Low";
                    var riskColor = riskScore == "Critical" ? Colors.Red.Medium : riskScore == "High" ? Colors.Orange.Medium : Colors.Green.Medium;
                    table.Cell().Element(CellStyle).Text(riskScore).FontColor(riskColor).Bold();

                    static IContainer CellStyle(IContainer container)
                    {
                        return container.Border(1).BorderColor(Colors.Grey.Lighten2).Padding(10).AlignCenter();
                    }
                });
            });
        }

        void ComposeCharts(IContainer container, ScanStatistics stats)
        {
            container.Column(column =>
            {
                column.Item().Text("Visual Analysis").FontSize(18).SemiBold().FontColor(Colors.Grey.Darken3);
                
                column.Item().PaddingTop(10).Row(row =>
                {
                    // Bar Chart: Violations by File Type (Replacing Severity Chart as per request)
                    row.RelativeItem().PaddingRight(10).Element(c => ComposeFileTypeChart(c, stats));
                    
                    // Pie Chart: Violations by Category
                    row.RelativeItem().PaddingLeft(10).Element(c => ComposeCategoryPieChart(c, stats));
                });
            });
        }

        void ComposeFileTypeChart(IContainer container, ScanStatistics stats)
        {
            container.Column(column =>
            {
                column.Item().Text("Violations by File Type").FontSize(14).SemiBold().FontColor(Colors.Grey.Darken2);
                
                if (stats.ViolationsByFileType == null || !stats.ViolationsByFileType.Any())
                {
                    column.Item().Text("No data available").Italic();
                    return;
                }

                var maxVal = stats.ViolationsByFileType.Values.DefaultIfEmpty(0).Max();
                
                column.Item().PaddingTop(10).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(60); // Label
                        columns.RelativeColumn();   // Bar
                        columns.ConstantColumn(40); // Value
                    });

                    foreach (var item in stats.ViolationsByFileType.OrderByDescending(x => x.Value))
                    {
                        table.Cell().Text(item.Key).FontSize(10);
                        
                        table.Cell().PaddingVertical(2).PaddingRight(5).AlignLeft().Row(row => 
                        {
                            var percentageOfMax = maxVal > 0 ? (float)item.Value / maxVal : 0;
                            
                            // Ensure percentageOfMax is strictly positive for QuestPDF, otherwise use a minimal value or don't render the bar item
                            // QuestPDF throws if RelativeItem size <= 0
                            
                            if (percentageOfMax > 0.001f)
                            {
                                // Assign a color based on file type or just cycle through colors
                                var colors = new[] { Colors.Blue.Medium, Colors.Green.Medium, Colors.Orange.Medium, Colors.Purple.Medium, Colors.Red.Medium };
                                var color = colors[Math.Abs(item.Key.GetHashCode()) % colors.Length];
                                row.RelativeItem(percentageOfMax).Height(15).Background(color);
                            }
                            else 
                            {
                                // If value is 0 or extremely small, just show a tiny sliver or nothing
                                // But row structure expects relative items to sum up? 
                                // Actually relative items share space. If one is 0, it might throw.
                                // If 0, we can skip adding the bar item.
                            }

                            // The spacer
                            var spacer = 1 - percentageOfMax;
                            if (spacer < 0) spacer = 0;
                            
                            if (spacer > 0.001f)
                            {
                                row.RelativeItem(spacer); 
                            }
                        });

                        table.Cell().Text(item.Value.ToString()).FontSize(10);
                    }
                });
            });
        }

        void ComposeCategoryPieChart(IContainer container, ScanStatistics stats)
        {
            var total = stats.ViolationsByCategory?.Values.Sum() ?? 0;

            container.Column(column =>
            {
                column.Item().Text("Violations by Category").FontSize(14).SemiBold().FontColor(Colors.Grey.Darken2);
                
                if (stats.ViolationsByCategory == null || !stats.ViolationsByCategory.Any())
                {
                    column.Item().Text("No data available").Italic();
                    return;
                }

                // Drawing a Pie Chart using SVG (since Canvas is deprecated in QuestPDF 2024.3+)
                try 
                {
                    column.Item().PaddingTop(10).Height(200).Svg(size =>
                    {
                        using var stream = new MemoryStream();
                        // SKSvgCanvas.Create returns an SKCanvas that writes SVG content to the stream
                        using (var canvas = SKSvgCanvas.Create(new SKRect(0, 0, size.Width, size.Height), stream))
                        {
                            if (total == 0) return "";
                            
                            var center = new SKPoint(size.Width / 2, size.Height / 2);
                            var radius = Math.Min(size.Width, size.Height) / 2 * 0.8f;
                            
                            float startAngle = 0;
                            var skColors = new[] { SKColors.Blue, SKColors.Green, SKColors.Red, SKColors.Orange, SKColors.Purple, SKColors.Teal };
                            int colorIndex = 0;

                            foreach (var item in stats.ViolationsByCategory.OrderByDescending(x => x.Value))
                            {
                                float sweepAngle = (float)item.Value / total * 360;
                                
                                using var paint = new SKPaint
                                {
                                    Color = skColors[colorIndex % skColors.Length],
                                    Style = SKPaintStyle.Fill,
                                    IsAntialias = true
                                };

                                using var path = new SKPath();
                                path.MoveTo(center);
                                path.ArcTo(new SKRect(center.X - radius, center.Y - radius, center.X + radius, center.Y + radius), startAngle, sweepAngle, false);
                                path.Close();

                                canvas.DrawPath(path, paint);
                                
                                startAngle += sweepAngle;
                                colorIndex++;
                            }
                        }

                        stream.Position = 0;
                        using var reader = new StreamReader(stream);
                        return reader.ReadToEnd();
                    });
                }
                catch (Exception ex)
                {
                    column.Item().Text($"Chart generation failed: {ex.Message}").FontColor(Colors.Red.Medium);
                }

                // Legend
                column.Item().PaddingTop(10).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(15);
                        columns.RelativeColumn();
                        columns.ConstantColumn(40);
                    });

                    int idx = 0;
                    var colors = new[] { Colors.Blue.Medium, Colors.Green.Medium, Colors.Red.Medium, Colors.Orange.Medium, Colors.Purple.Medium, Colors.Teal.Medium };

                    foreach (var item in stats.ViolationsByCategory.OrderByDescending(x => x.Value))
                    {
                        table.Cell().Height(10).Width(10).Background(colors[idx % colors.Length]);
                        table.Cell().PaddingLeft(5).Text(item.Key).FontSize(10);
                        
                        var pct = total > 0 ? (item.Value * 100.0 / total).ToString("F1") + "%" : "0%";
                        table.Cell().Text(pct).FontSize(10).AlignRight();
                        
                        idx++;
                    }
                });
            });
        }

        void ComposeTopViolations(IContainer container, ScanStatistics stats)
        {
            container.Column(column =>
            {
                column.Item().Text("Top Findings & Recommendations").FontSize(18).SemiBold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingBottom(10).Text("Prioritize these issues to improve your compliance score.").FontSize(10).Italic().FontColor(Colors.Grey.Darken1);

                foreach (var violation in stats.TopViolations)
                {
                    column.Item().PaddingVertical(5).Element(c => 
                    {
                        c.Border(1).BorderColor(Colors.Grey.Lighten2).Background(Colors.Grey.Lighten4).Padding(10).Column(col =>
                        {
                            col.Item().Row(row =>
                            {
                                row.RelativeItem().Text(violation.RuleName).Bold().FontSize(12);
                                row.ConstantItem(100).AlignRight().Text($"{violation.Count} Occurrences").Bold().FontColor(Colors.Red.Medium);
                            });

                            col.Item().PaddingTop(5).Text($"Category: {violation.Category} | ID: {violation.RuleId}").FontSize(10).FontColor(Colors.Grey.Darken2);
                            
                            col.Item().PaddingTop(10).Text("Solution:").SemiBold().FontSize(10);
                            col.Item().Text(violation.SuggestiveSolution).FontSize(10);

                            if (!string.IsNullOrEmpty(violation.ReferenceUrl))
                            {
                                col.Item().PaddingTop(5).Text("Reference:").SemiBold().FontSize(10);
                                col.Item().Hyperlink(violation.ReferenceUrl).Text(violation.ReferenceUrl).FontSize(10).FontColor(Colors.Blue.Medium).Underline();
                            }
                        });
                    });
                }
            });
        }

        string GetSeverityColor(string severity)
        {
            return severity.ToLower() switch
            {
                "critical" => Colors.Red.Medium,
                "high" => Colors.Orange.Medium,
                "medium" => Colors.Amber.Medium,
                "low" => Colors.Blue.Medium,
                _ => Colors.Grey.Medium
            };
        }
    }
}
